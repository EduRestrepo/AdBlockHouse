// C3 AdBlock PRO — High-Performance DNS Sinkhole & Modern Dashboard for ESP32-C3
// Features: 40-bit FNV-1a Hash in Flash + RAM Checkpoint Index, In-Memory DNS Cache,
// Whitelist, Dual-Upstream DNS with Auto-Failover, IPv6 AAAA sinkholing, Client Aliases,
// Live Query Log, Captive Portal, and WiFi OTA updates.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoOTA.h>
#include <DNSServer.h>
#include <Preferences.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"

#if __has_include("secrets.h")
  #include "secrets.h"
#else
  static const char* WIFI_SSID = "YOUR_WIFI_SSID";
  static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
#endif

// ---- Configurations & Constants ----
static IPAddress upstreamPrimary(9, 9, 9, 9);    // Default: Quad9
static IPAddress upstreamSecondary(1, 1, 1, 1);  // Default: Cloudflare
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// ---- Global State ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0, cacheHits = 0;
uint8_t buf[600];

// ---- RAM Checkpoint Index for Flash Search ----
// Drastically cuts flash binary search reads from ~18 to ~5-7
static const int NUM_CHECKPOINTS = 1024;
static uint64_t checkpoints[NUM_CHECKPOINTS];
static uint32_t numCheckpoints = 0;
static uint32_t checkpointStep = 0;

static void buildCheckpoints() {
  numCheckpoints = 0;
  if (!blocklist || numHashes == 0) return;
  numCheckpoints = (numHashes < NUM_CHECKPOINTS) ? numHashes : NUM_CHECKPOINTS;
  checkpointStep = numHashes / numCheckpoints;
  uint8_t b[HASH_BYTES];
  for (uint32_t i = 0; i < numCheckpoints; i++) {
    blocklist.seek(i * checkpointStep * HASH_BYTES);
    blocklist.read(b, HASH_BYTES);
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= ((uint64_t)b[k]) << (8 * k);
    checkpoints[i] = v;
  }
}

// ---- In-Memory DNS LRU Cache ----
struct DnsCacheEntry {
  uint64_t hash;
  uint16_t qtype;
  uint32_t expiresAt;
  uint16_t len;
  uint8_t pkt[180];
};
static const int CACHE_SIZE = 96;
static DnsCacheEntry dnsCache[CACHE_SIZE];
static int cacheNextIdx = 0;

static bool checkCache(uint64_t h, uint16_t qtype, uint8_t* out, int* outLen, uint16_t txid) {
  uint32_t now = millis();
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (dnsCache[i].len > 0 && dnsCache[i].hash == h && dnsCache[i].qtype == qtype) {
      if (now < dnsCache[i].expiresAt) {
        memcpy(out, dnsCache[i].pkt, dnsCache[i].len);
        out[0] = (uint8_t)(txid >> 8);
        out[1] = (uint8_t)(txid & 0xFF);
        *outLen = dnsCache[i].len;
        cacheHits++;
        return true;
      }
    }
  }
  return false;
}

static void storeCache(uint64_t h, uint16_t qtype, const uint8_t* inPkt, int len, int qend) {
  if (len > (int)sizeof(dnsCache[0].pkt) || len < 12) return;
  uint16_t ancount = (inPkt[6] << 8) | inPkt[7];
  if (ancount == 0) return; // Don't cache error / empty responses
  
  // Extract TTL from first answer record (4 bytes at qend + 6)
  uint32_t ttl = 120;
  if (qend + 10 <= len) {
    ttl = ((uint32_t)inPkt[qend + 6] << 24) | ((uint32_t)inPkt[qend + 7] << 16) |
          ((uint32_t)inPkt[qend + 8] << 8)  | ((uint32_t)inPkt[qend + 9]);
  }
  if (ttl < 15) ttl = 15;
  if (ttl > 1800) ttl = 1800; // Cap at 30 min in local cache

  DnsCacheEntry& e = dnsCache[cacheNextIdx];
  cacheNextIdx = (cacheNextIdx + 1) % CACHE_SIZE;
  e.hash = h;
  e.qtype = qtype;
  e.len = len;
  e.expiresAt = millis() + (ttl * 1000UL);
  memcpy(e.pkt, inPkt, len);
}

// ---- Client Table ----
struct Dev {
  uint32_t ip;
  uint8_t mac[6];
  uint32_t blocked, allowed, lastSeen;
  bool banned;
  String label;
};
static const int MAX_CLIENTS = 96;
static Dev clients[MAX_CLIENTS];
static int numClients = 0;

static const int MAX_CUSTOM = 200;
static String customDom[MAX_CUSTOM];
static uint64_t customHash[MAX_CUSTOM];
static int numCustom = 0;

static const int MAX_ALLOW = 150;
static String allowDom[MAX_ALLOW];
static uint64_t allowHash[MAX_ALLOW];
static int numAllow = 0;

static const int MAX_BAN = 32;
static uint32_t bannedIP[MAX_BAN];
static int numBanned = 0;

// Remote blocklist auto-update
static String updateUrl = "";
static uint32_t updateIntervalH = 24;
static uint32_t lastCheckMs = 0;
static String updateStatus = "never";

// WiFi provisioning (captive portal)
static Preferences prefs;
static DNSServer   dnsPortal;
static String      portalOpts;

// Blocking pause
static bool     blockingOn = true;
static uint32_t resumeAt   = 0;

// ---- Live Query Log Ring Buffer ----
struct QueryLogEntry {
  uint32_t timeMs;
  uint32_t ip;
  char domain[72];
  uint16_t qtype;
  uint8_t status; // 0=Blocked (list), 1=Blocked (custom), 2=Allowed (upstream), 3=Allowed (cache), 4=Allowed (whitelist), 5=Banned
};
static const int LOG_CAP = 64;
static QueryLogEntry queryLog[LOG_CAP];
static int logHead = 0;
static int logCount = 0;

static void addLog(uint32_t ip, const char* dom, uint16_t qtype, uint8_t status) {
  QueryLogEntry& e = queryLog[logHead];
  e.timeMs = millis();
  e.ip = ip;
  e.qtype = qtype;
  e.status = status;
  strncpy(e.domain, dom, sizeof(e.domain) - 1);
  e.domain[sizeof(e.domain) - 1] = 0;
  logHead = (logHead + 1) % LOG_CAP;
  if (logCount < LOG_CAP) logCount++;
}

// ---------- Hashing & Matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}

static bool inFlash(uint64_t h) {
  if (!blocklist || numHashes == 0) return false;
  int32_t lo = 0, hi = (int32_t)numHashes - 1;

  // Use RAM Checkpoint table to narrow the binary search window
  if (numCheckpoints > 0 && checkpointStep > 0) {
    int32_t c_lo = 0, c_hi = (int32_t)numCheckpoints - 1;
    int32_t c_match = 0;
    while (c_lo <= c_hi) {
      int32_t mid = (c_lo + c_hi) >> 1;
      if (checkpoints[mid] <= h) {
        c_match = mid;
        c_lo = mid + 1;
      } else {
        c_hi = mid - 1;
      }
    }
    lo = c_match * checkpointStep;
    hi = min((int32_t)numHashes - 1, (int32_t)(c_match + 2) * (int32_t)checkpointStep);
  }

  uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    blocklist.seek((uint32_t)mid * HASH_BYTES);
    blocklist.read(b, HASH_BYTES);
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= ((uint64_t)b[k]) << (8 * k);
    if (v < h) lo = mid + 1;
    else if (v > h) hi = mid - 1;
    else return true;
  }
  return false;
}

static bool inCustom(uint64_t h) {
  for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true;
  return false;
}

static bool inAllow(uint64_t h) {
  for (int i = 0; i < numAllow; i++) if (allowHash[i] == h) return true;
  return false;
}

static bool isAllowed(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inAllow(h)) return true;
    const char* dot = strchr(p, '.');
    if (!dot) break;
    const char* next = dot + 1;
    if (!strchr(next, '.')) break;
    p = next;
  }
  return false;
}

static bool isBlocked(const char* domain, bool* isCustomOut) {
  if (isCustomOut) *isCustomOut = false;
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inCustom(h)) {
      if (isCustomOut) *isCustomOut = true;
      return true;
    }
    if (inFlash(h)) return true;
    const char* dot = strchr(p, '.');
    if (!dot) break;
    const char* next = dot + 1;
    if (!strchr(next, '.')) break;
    p = next;
  }
  return false;
}

// ---------- Persistence ----------
static void loadCustom() {
  numCustom = 0;
  File f = LittleFS.open("/custom.txt", "r");
  if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) {
      customDom[numCustom] = l;
      customHash[numCustom] = fnv40(l.c_str(), l.length());
      numCustom++;
    }
  }
  f.close();
}

static void saveCustom() {
  File f = LittleFS.open("/custom.txt", "w");
  if (!f) return;
  for (int i = 0; i < numCustom; i++) f.println(customDom[i]);
  f.close();
}

static bool addCustom(String d) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d;
  customHash[numCustom] = fnv40(d.c_str(), d.length());
  numCustom++;
  saveCustom();
  return true;
}

static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) {
    if (customDom[i] == d) {
      for (int j = i; j < numCustom - 1; j++) {
        customDom[j] = customDom[j+1];
        customHash[j] = customHash[j+1];
      }
      numCustom--;
      saveCustom();
      return;
    }
  }
}

static void loadAllow() {
  numAllow = 0;
  File f = LittleFS.open("/allowlist.txt", "r");
  if (!f) return;
  while (f.available() && numAllow < MAX_ALLOW) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) {
      allowDom[numAllow] = l;
      allowHash[numAllow] = fnv40(l.c_str(), l.length());
      numAllow++;
    }
  }
  f.close();
}

static void saveAllow() {
  File f = LittleFS.open("/allowlist.txt", "w");
  if (!f) return;
  for (int i = 0; i < numAllow; i++) f.println(allowDom[i]);
  f.close();
}

static bool addAllow(String d) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numAllow >= MAX_ALLOW) return false;
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) return false;
  allowDom[numAllow] = d;
  allowHash[numAllow] = fnv40(d.c_str(), d.length());
  numAllow++;
  saveAllow();
  return true;
}

static void removeAllow(String d) {
  d.toLowerCase();
  for (int i = 0; i < numAllow; i++) {
    if (allowDom[i] == d) {
      for (int j = i; j < numAllow - 1; j++) {
        allowDom[j] = allowDom[j+1];
        allowHash[j] = allowHash[j+1];
      }
      numAllow--;
      saveAllow();
      return;
    }
  }
}

static bool isBannedIP(uint32_t ip) {
  for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true;
  return false;
}

static void loadBanned() {
  numBanned = 0;
  File f = LittleFS.open("/banned.txt", "r");
  if (!f) return;
  while (f.available() && numBanned < MAX_BAN) {
    String l = f.readStringUntil('\n'); l.trim();
    IPAddress ip;
    if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip;
  }
  f.close();
}

static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) {
    if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  }
  File f = LittleFS.open("/banned.txt", "w");
  if (!f) return;
  for (int i = 0; i < numBanned; i++) {
    IPAddress ip(bannedIP[i]);
    f.println(ip.toString());
  }
  f.close();
}

static void loadDnsCfg() {
  File f = LittleFS.open("/dns.cfg", "r");
  if (!f) return;
  String p = f.readStringUntil('\n'); p.trim();
  String s = f.readStringUntil('\n'); s.trim();
  IPAddress ip;
  if (p.length() && ip.fromString(p)) upstreamPrimary = ip;
  if (s.length() && ip.fromString(s)) upstreamSecondary = ip;
  f.close();
}

static void saveDnsCfg() {
  File f = LittleFS.open("/dns.cfg", "w");
  if (!f) return;
  f.println(upstreamPrimary.toString());
  f.println(upstreamSecondary.toString());
  f.close();
}

static void loadLabels() {
  File f = LittleFS.open("/labels.txt", "r");
  if (!f) return;
  while (f.available()) {
    String l = f.readStringUntil('\n'); l.trim();
    int sep = l.indexOf(',');
    if (sep > 0) {
      String ipStr = l.substring(0, sep);
      String lbl = l.substring(sep + 1);
      IPAddress ip;
      if (ip.fromString(ipStr)) {
        for (int i = 0; i < numClients; i++) {
          if (clients[i].ip == (uint32_t)ip) {
            clients[i].label = lbl;
            break;
          }
        }
      }
    }
  }
  f.close();
}

static void saveLabels() {
  File f = LittleFS.open("/labels.txt", "w");
  if (!f) return;
  for (int i = 0; i < numClients; i++) {
    if (clients[i].label.length()) {
      IPAddress ip(clients[i].ip);
      f.print(ip.toString());
      f.print(",");
      f.println(clients[i].label);
    }
  }
  f.close();
}

// ---------- Client Management ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6);
  ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr;
  const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next) {
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) {
      memcpy(mac, eth->addr, 6);
      return;
    }
  }
}

static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) {
    if (clients[i].ip == ip) {
      clients[i].lastSeen = millis();
      return &clients[i];
    }
  }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip;
    c->blocked = c->allowed = 0;
    c->lastSeen = millis();
    c->banned = isBannedIP(ip);
    c->label = "";
    getMac(ip, c->mac);
    return c;
  }
  return nullptr;
}

// ---------- DNS Core ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12;
  size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++];
    if (l == 0) break;
    if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]);
  }
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = (pkt[i] << 8) | pkt[i + 1];
  *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) {
    memmove(out, out + 4, o - 3);
    o -= 4;
  }
  return o;
}

static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; // Standard response, No Error
  buf[4] = 0; buf[5] = 1;       // QDCOUNT = 1
  buf[6] = 0; buf[7] = 1;       // ANCOUNT = 1
  buf[8] = 0; buf[9] = 0;       // NSCOUNT = 0
  buf[10] = 0; buf[11] = 0;     // ARCOUNT = 0

  if (qtype == 1) { // IPv4 A record -> 0.0.0.0
    const uint8_t ansA[] = {
      0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
      0, 0, 0, 0
    };
    memcpy(buf + qend, ansA, sizeof(ansA));
    return qend + sizeof(ansA);
  } else if (qtype == 28) { // IPv6 AAAA record -> ::
    const uint8_t ansAAAA[] = {
      0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x10,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
    };
    memcpy(buf + qend, ansAAAA, sizeof(ansAAAA));
    return qend + sizeof(ansAAAA);
  } else {
    buf[7] = 0; // ANCOUNT = 0 (NODATA synthesis for other types)
    return qend;
  }
}

// Dual Upstream DNS forwarding with fast failover
static int forwardUpstream(int qlen) {
  // Primary upstream attempt (Quad9 default, 350ms timeout)
  upstreamCli.beginPacket(upstreamPrimary, 53);
  upstreamCli.write(buf, qlen);
  upstreamCli.endPacket();

  uint32_t t0 = millis();
  while (millis() - t0 < 350) {
    int sz = upstreamCli.parsePacket();
    if (sz > 0) return upstreamCli.read(buf, sizeof(buf));
    delay(1);
  }

  // Fallback to secondary upstream (Cloudflare default, 450ms timeout)
  upstreamCli.beginPacket(upstreamSecondary, 53);
  upstreamCli.write(buf, qlen);
  upstreamCli.endPacket();

  t0 = millis();
  while (millis() - t0 < 450) {
    int sz = upstreamCli.parsePacket();
    if (sz > 0) return upstreamCli.read(buf, sizeof(buf));
    delay(1);
  }

  return 0; // Neither replied
}

static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket();
    if (sz <= 0) break;
    did = true;

    IPAddress cip = dnsServer.remoteIP();
    uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf));
    if (qlen < 13) continue;

    uint16_t txid = ((uint16_t)buf[0] << 8) | buf[1];
    char domain[256];
    uint16_t qtype = 0;
    int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);

    if (c && c->banned) {
      int rlen = buildBlocked(qend, qtype);
      totalBlocked++;
      c->blocked++;
      addLog((uint32_t)cip, domain, qtype, 5); // 5=Banned
      dnsServer.beginPacket(cip, cport);
      dnsServer.write(buf, rlen);
      dnsServer.endPacket();
      continue;
    }

    // Whitelist check
    if (dl && isAllowed(domain)) {
      int rlen = 0;
      uint64_t dh = fnv40(domain, dl);
      if (checkCache(dh, qtype, buf, &rlen, txid)) {
        addLog((uint32_t)cip, domain, qtype, 3); // 3=Cache
      } else {
        rlen = forwardUpstream(qlen);
        if (rlen > 0) storeCache(dh, qtype, buf, rlen, qend);
        addLog((uint32_t)cip, domain, qtype, 4); // 4=Whitelist
      }
      totalAllowed++;
      if (c) c->allowed++;
      if (rlen > 0) {
        dnsServer.beginPacket(cip, cport);
        dnsServer.write(buf, rlen);
        dnsServer.endPacket();
      }
      continue;
    }

    // Blocklist check
    bool isCustom = false;
    bool blocked = blockingOn && dl && (numHashes || numCustom) && isBlocked(domain, &isCustom);

    int rlen = 0;
    if (blocked) {
      rlen = buildBlocked(qend, qtype);
      totalBlocked++;
      if (c) c->blocked++;
      addLog((uint32_t)cip, domain, qtype, isCustom ? 1 : 0);
    } else {
      uint64_t dh = dl ? fnv40(domain, dl) : 0;
      if (dl && checkCache(dh, qtype, buf, &rlen, txid)) {
        addLog((uint32_t)cip, domain, qtype, 3); // Cache hit
      } else {
        rlen = forwardUpstream(qlen);
        if (rlen > 0 && dl) storeCache(dh, qtype, buf, rlen, qend);
        addLog((uint32_t)cip, domain, qtype, 2); // Upstream
      }
      totalAllowed++;
      if (c) c->allowed++;
    }

    if (rlen > 0) {
      dnsServer.beginPacket(cip, cport);
      dnsServer.write(buf, rlen);
      dnsServer.endPacket();
    }
  }
  return did;
}

// ---------- Web & Dashboard ----------
static String macStr(const uint8_t* m) {
  char s[18];
  snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(s);
}

static String jesc(const String& s) {
  String o;
  for (char ch : s) {
    if (ch == '"' || ch == '\\') o += '\\';
    o += ch;
  }
  return o;
}

#include "page.h"

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24];
  snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);

  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked +
             ",\"allowed\":" + totalAllowed + ",\"cacheHits\":" + cacheHits +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() +
             ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"dnsPri\":\"" + upstreamPrimary.toString() + "\",\"dnsSec\":\"" + upstreamSecondary.toString() + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH +
             ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"clients\":[";

  for (int i = 0; i < numClients; i++) {
    Dev& c = clients[i];
    IPAddress ip(c.ip);
    if (i) j += ",";
    j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"label\":\"" + jesc(c.label) +
         "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned ? "true" : "false") + "}";
  }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) {
    if (i) j += ",";
    j += "\"" + jesc(customDom[i]) + "\"";
  }
  j += "],\"whitelist\":[";
  for (int i = 0; i < numAllow; i++) {
    if (i) j += ",";
    j += "\"" + jesc(allowDom[i]) + "\"";
  }
  j += "]}";
  web.send(200, "application/json", j);
}

static void handleLog() {
  uint32_t now = millis();
  String j = "[";
  for (int i = 0; i < logCount; i++) {
    int idx = (logHead - 1 - i + LOG_CAP) % LOG_CAP;
    QueryLogEntry& e = queryLog[idx];
    IPAddress ip(e.ip);
    uint32_t ago = (now - e.timeMs) / 1000;
    if (i) j += ",";
    j += "{\"t\":" + String(ago) + ",\"ip\":\"" + ip.toString() + "\",\"q\":" + e.qtype +
         ",\"d\":\"" + jesc(e.domain) + "\",\"st\":" + e.status + "}";
  }
  j += "]";
  web.send(200, "application/json", j);
}

static void handleBan() {
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    Dev* c = getClient((uint32_t)ip);
    if (c) {
      c->banned = !c->banned;
      saveBanned();
    }
  }
  web.send(200, "text/plain", "ok");
}

static void handleSetLabel() {
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    Dev* c = getClient((uint32_t)ip);
    if (c) {
      c->label = web.arg("name");
      saveLabels();
    }
  }
  web.send(200, "text/plain", "ok");
}

static void handleSetUpstream() {
  IPAddress p, s;
  if (p.fromString(web.arg("p"))) upstreamPrimary = p;
  if (s.fromString(web.arg("s"))) upstreamSecondary = s;
  saveDnsCfg();
  web.send(200, "text/plain", "ok");
}

// ---------- Blocklist Swap & OTA ----------
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildCheckpoints();
}

static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  numCheckpoints = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}

static bool commitNewBlocklist() {
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0;
  if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

static bool upOk = false;
static File upFile;

static void handleUploadDone() {
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
}

static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upOk = false;
      beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new");
      reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// Remote blocklist auto-update
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r");
  if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim();
  if (iv.length()) updateIntervalH = iv.toInt();
  f.close();
  if (updateIntervalH < 1) updateIntervalH = 1;
}

static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w");
  if (!f) return;
  f.println(updateUrl);
  f.println(updateIntervalH);
  f.close();
}

static bool fetchBlocklist(String url) {
  url.trim();
  if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();
  WiFiClient cl;
  HTTPClient http;
  http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) {
    updateStatus = "begin failed";
    return false;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    http.end();
    updateStatus = "HTTP " + String(code);
    return false;
  }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) {
    http.end();
    updateStatus = "fs open failed";
    reopenBlocklist();
    return false;
  }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize();
  uint8_t b[1024];
  size_t total = 0;
  uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) {
      int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) { f.write(b, n); total += n; idle = millis(); }
    } else {
      if (millis() - idle > 15000) break;
      delay(2);
    }
  }
  f.close();
  http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  return ok;
}

// Firmware OTA
static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}

static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort();
    Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi Provisioning (Captive Portal) ----------
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; Configurar WiFi</h2>"
    "<p style='color:#8b949e'>Selecciona tu red de casa e introduce la clave. El dispositivo se conectará automáticamente.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='Nombre de WiFi' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Contraseña' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#38bdf8;color:#000;font-weight:600;cursor:pointer'>Conectar</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}

static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "Falta el nombre de WiFi"); return; }
  prefs.begin("wifi", false);
  prefs.putString("ssid", ss);
  prefs.putString("pass", pw);
  prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Guardado. Conectando a <b>" + ss + "</b>&hellip;<br><br>"
                             "Vuelve a conectar tu móvil a tu red WiFi habitual y abre <b>http://c3adblock.local</b>.</body>");
  delay(900);
  ESP.restart();
}

static void startConfigPortal() {
  int n = WiFi.scanNetworks();
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + jesc(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" (or http://%s)\n", ap, apIP.toString().c_str());
  while (true) {
    dnsPortal.processNextRequest();
    web.handleClient();
    delay(2);
  }
}

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n[c3-adblock-pro] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");

  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildCheckpoints();
    Serial.printf("RAM index: %u checkpoints built\n", numCheckpoints);
  }

  loadCustom();
  loadAllow();
  loadBanned();
  loadDnsCfg();
  loadUpdateCfg();
  loadLabels();

  // Reset WiFi when BOOT (GPIO9) held at startup
  pinMode(9, INPUT_PULLUP);
  if (digitalRead(9) == LOW) {
    delay(60);
    if (digitalRead(9) == LOW) {
      prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi");
    }
  }

  if (!connectWiFi()) startConfigPortal();
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());

  if (MDNS.begin("c3adblock")) {
    MDNS.addService("http", "tcp", 80);
    Serial.println("Dashboard: http://c3adblock.local");
  }

  dnsServer.begin(DNS_PORT);
  upstreamCli.begin(0);

  // Web Endpoints
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/log.json", handleLog);
  web.on("/ban", handleBan);
  web.on("/setlabel", handleSetLabel);
  web.on("/setupstream", handleSetUpstream);
  web.on("/addblock", []() { addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/addallow", []() { addAllow(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unallow", []() { removeAllow(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false;
    resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() {
    blockingOn = true;
    resumeAt = 0;
    web.send(200, "text/plain", "resumed");
  });
  web.on("/reboot", []() {
    web.send(200, "text/plain", "Rebooting...");
    delay(500);
    ESP.restart();
  });
  web.on("/forgetwifi", []() {
    web.send(200, "text/plain", "cleared — rebooting");
    prefs.begin("wifi", false); prefs.clear(); prefs.end();
    delay(500);
    ESP.restart();
  });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);
  web.on("/fetchnow", []() {
    fetchBlocklist(updateUrl);
    web.send(200, "text/plain", updateStatus);
  });
  web.on("/setupdate", []() {
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) {
      updateIntervalH = web.arg("h").toInt();
      if (updateIntervalH < 1) updateIntervalH = 1;
    }
    saveUpdateCfg();
    web.send(200, "text/plain", "ok");
  });

  web.begin();
  ArduinoOTA.setHostname("c3adblock");
  ArduinoOTA.begin();
  Serial.println("Ready: DNS :53 + Dashboard :80 + RAM Cache + Checkpoint Index");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();

  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) {
    blockingOn = true;
    resumeAt = 0;
  }

  if (updateUrl.length()) {
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) {
      lastCheckMs = now;
      fetchBlocklist(updateUrl);
    }
  }

  if (!busy) delay(1);
}
