// C3 AdBlock PRO — High-Performance DNS Sinkhole & Modern Dashboard for ESP32-C3
// Features: 40-bit FNV-1a Hash in Flash + RAM Checkpoint Index, In-Memory DNS Cache,
// Whitelist, Dual-Upstream DNS with Auto-Failover, IPv6 AAAA sinkholing, Client Aliases,
// Live Query Log, Captive Portal, and WiFi OTA updates.
// Also: async upstream forwarding (hedged, latency-aware), negative/stale/prefetch DNS cache,
// safe blocklist updates (ETag, validated, auto-retry), task watchdog + low-memory/WiFi
// self-healing, wildcard rules, SafeSearch, DoH blocking, persistent stats, config export/import.

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
#include <esp_task_wdt.h>
#include <esp_system.h>
#include <time.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "dnsutil.h"

#if __has_include("secrets.h")
  #include "secrets.h"
#else
  static const char* WIFI_SSID = "YOUR_WIFI_SSID";
  static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
#endif

// ---- Configurations & Constants ----
static IPAddress upstreamPrimary(1, 1, 1, 1);    // Default: Cloudflare (ultra-low latency)
static IPAddress upstreamSecondary(8, 8, 8, 8);  // Default: Google
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// Blocklist published daily by .github/workflows/update_blocklist.yml (used when no URL is configured)
static const char* DEFAULT_UPDATE_URL = "https://github.com/EduRestrepo/AdBlockHouse/releases/latest/download/blocklist.bin";
static const uint32_t MIN_LIST_ENTRIES = 1000;      // anything smaller is not a real blocklist
static const int64_t  FS_MARGIN = 64 * 1024;        // LittleFS metadata / block-rounding headroom

// Self-healing thresholds
static const uint32_t WDT_TIMEOUT_S = 45;           // task watchdog (loop task must check in)
static const uint32_t LOWMEM_FREE_BYTES = 20000;    // free heap below this for 30 s -> restart
static const uint32_t LOWMEM_BLOCK_BYTES = 8000;    // largest free block below this for 30 s -> restart

// ---- Global State ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0, cacheHits = 0, totalCnameBlocked = 0;
uint8_t buf[600];
static bool blockingOn = true;
static uint32_t resumeAt = 0;

// ---- Status LED (GPIO8 on ESP32-C3 SuperMini & DevKits) ----
static const int LED_PIN = 8;
static bool ledEnabled = true;
static uint32_t lastLedToggle = 0;
static bool ledState = false;
static uint32_t ledFlickerUntil = 0;

static void triggerLedBlockFlicker() {
  if (ledEnabled) {
    ledFlickerUntil = millis() + 60; // 60ms off-pulse on sinkholed ad/tracker
    digitalWrite(LED_PIN, HIGH);
  }
}

static void updateLed(bool isPortal = false) {
  if (!ledEnabled) {
    digitalWrite(LED_PIN, HIGH); // OFF (active-low)
    return;
  }
  uint32_t now = millis();
  if (isPortal) {
    if (now - lastLedToggle >= 100) { // Fast blink in captive portal
      lastLedToggle = now;
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState ? LOW : HIGH);
    }
  } else if (!blockingOn) {
    if (now - lastLedToggle >= 600) { // Slow blink when paused
      lastLedToggle = now;
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState ? LOW : HIGH);
    }
  } else {
    if (now < ledFlickerUntil) {
      digitalWrite(LED_PIN, HIGH); // Off-pulse on blocked query
    } else {
      digitalWrite(LED_PIN, LOW);  // Solid ON when actively protecting
    }
  }
}

static void loadLedCfg() {
  File f = LittleFS.open("/led.cfg", "r");
  if (!f) return;
  String s = f.readStringUntil('\n'); s.trim();
  if (s == "0") ledEnabled = false;
  f.close();
}

static void saveLedCfg() {
  File f = LittleFS.open("/led.cfg", "w");
  if (!f) return;
  f.println(ledEnabled ? "1" : "0");
  f.close();
}

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

// ---- In-Memory DNS Cache: positive + negative entries, serve-stale and prefetch ----
// Entries are keyed by the FULL query name (not the www-stripped one used for list matching),
// so "www.example.com" and "example.com" never share a response.
struct DnsCacheEntry {
  uint64_t hash;
  uint32_t expiresAt;
  uint16_t qtype;
  uint16_t len;
  uint16_t ttl;      // original TTL in seconds (drives the prefetch window)
  uint8_t hits;
  uint8_t flags;
  uint8_t pkt[180];
};
static const uint8_t CF_REFRESHING = 1;   // a background refresh is already in flight
static const uint8_t CF_NEGATIVE = 2;     // NXDOMAIN / NODATA entry
static const int CACHE_SIZE = 256;
static DnsCacheEntry dnsCache[CACHE_SIZE];
static int cacheNextIdx = 0;
static const uint32_t CACHE_STALE_MS = 15UL * 60UL * 1000UL;  // serve expired answers up to 15 min old
static const uint32_t NEG_TTL_S = 60;                          // negative answers are kept 60 s
enum { CACHE_MISS = 0, CACHE_FRESH = 1, CACHE_STALE = 2 };

static int findCacheSlot(uint64_t h, uint16_t qtype) {
  for (int i = 0; i < CACHE_SIZE; i++)
    if (dnsCache[i].len > 0 && dnsCache[i].hash == h && dnsCache[i].qtype == qtype) return i;
  return -1;
}

static void clearCache() {
  for (int i = 0; i < CACHE_SIZE; i++) dnsCache[i].len = 0;
}

static void clearRefreshing(uint64_t h, uint16_t qtype) {
  int i = findCacheSlot(h, qtype);
  if (i >= 0) dnsCache[i].flags &= (uint8_t)~CF_REFRESHING;
}

static void invalidateCache(uint64_t h, uint16_t qtype) {
  int i = findCacheSlot(h, qtype);
  if (i >= 0) dnsCache[i].len = 0;
}

// Copies a cached response into `out` (TTLs rewritten to what is really left).
// Returns CACHE_FRESH, CACHE_STALE (expired but inside the stale window; only if allowStale) or CACHE_MISS.
// *needRefresh is set when the caller should refresh the entry in the background.
static int checkCache(uint64_t h, uint16_t qtype, uint8_t* out, int* outLen, uint16_t txid,
                      int qend, bool allowStale, bool* needRefresh) {
  *needRefresh = false;
  int i = findCacheSlot(h, qtype);
  if (i < 0) return CACHE_MISS;
  DnsCacheEntry& e = dnsCache[i];
  int32_t remain = (int32_t)(e.expiresAt - millis());
  int state;
  if (remain > 0) state = CACHE_FRESH;
  else if (allowStale && (uint32_t)(-remain) < CACHE_STALE_MS) state = CACHE_STALE;
  else return CACHE_MISS;

  memcpy(out, e.pkt, e.len);
  out[0] = (uint8_t)(txid >> 8);
  out[1] = (uint8_t)(txid & 0xFF);
  *outLen = e.len;
  uint32_t ttlOut = (state == CACHE_FRESH) ? (uint32_t)((remain + 999) / 1000) : 30;  // RFC 8767: stale answers carry 30 s
  if (ttlOut < 1) ttlOut = 1;
  dnsWalkTtls(out, e.len, qend, nullptr, true, ttlOut);

  if (e.hits < 255) e.hits++;
  if (!(e.flags & CF_REFRESHING)) {
    uint32_t window = (uint32_t)e.ttl * 100UL;   // prefetch popular names during the last 10% of their TTL...
    if (window > 30000UL) window = 30000UL;      // ...but never earlier than 30 s before expiry
    if (state == CACHE_STALE ||
        (e.hits >= 3 && !(e.flags & CF_NEGATIVE) && (uint32_t)remain < window)) {
      *needRefresh = true;
      e.flags |= CF_REFRESHING;
    }
  }
  cacheHits++;
  return state;
}

static void storeCache(uint64_t h, uint16_t qtype, const uint8_t* inPkt, int len, int qend) {
  if (len > (int)sizeof(dnsCache[0].pkt) || len < 12) return;
  if (inPkt[2] & 0x02) return;                       // truncated (TC) responses are never cached
  uint8_t rcode = inPkt[3] & 0x0F;
  uint16_t ancount = ((uint16_t)inPkt[6] << 8) | inPkt[7];
  uint8_t flags = 0;
  uint32_t ttl;
  if (rcode == 3 || (rcode == 0 && ancount == 0)) {  // NXDOMAIN / NODATA -> short negative cache
    ttl = NEG_TTL_S;
    flags |= CF_NEGATIVE;
  } else if (rcode == 0) {
    uint32_t mn = 0xFFFFFFFFUL;
    ttl = 120;
    if (dnsWalkTtls(const_cast<uint8_t*>(inPkt), len, qend, &mn, false, 0) && mn != 0xFFFFFFFFUL) ttl = mn;
  } else {
    return;                                          // SERVFAIL / REFUSED / ... are never cached
  }
  if (ttl < 15) ttl = 15;
  if (ttl > 1800) ttl = 1800; // Cap at 30 min in local cache

  int slot = findCacheSlot(h, qtype);
  uint8_t keepHits = 0;
  if (slot >= 0) keepHits = dnsCache[slot].hits;     // refreshing an entry keeps its popularity
  else {
    slot = cacheNextIdx;
    cacheNextIdx = (cacheNextIdx + 1) % CACHE_SIZE;
  }
  DnsCacheEntry& e = dnsCache[slot];
  e.hash = h;
  e.qtype = qtype;
  e.len = len;
  e.ttl = (uint16_t)ttl;
  e.hits = keepHits;
  e.flags = flags;
  e.expiresAt = millis() + (ttl * 1000UL);
  memcpy(e.pkt, inPkt, len);
}

// A cached response echoes the question of whoever asked first; give every client back ITS question
// (same length, possibly different letter case) so strict resolvers accept the answer.
static void fixQuestion(uint8_t* pkt, int pktLen, const uint8_t* q, int qend) {
  if (qend > 12 && pktLen >= qend) memcpy(pkt + 12, q + 12, qend - 12);
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

// Rules are exact domains (matched with all their subdomains) or wildcard patterns containing '*' / '?'
static const int MAX_CUSTOM = 400;
static String customDom[MAX_CUSTOM];
static uint64_t customHash[MAX_CUSTOM];
static bool customWild[MAX_CUSTOM];
static int numCustom = 0;

static const int MAX_ALLOW = 300;
static String allowDom[MAX_ALLOW];
static uint64_t allowHash[MAX_ALLOW];
static bool allowWild[MAX_ALLOW];
static int numAllow = 0;

// Bumped on every rule change so the dashboard only re-downloads the lists when they changed
static uint32_t listVersion = 1;

static const int MAX_BAN = 32;
static uint32_t bannedIP[MAX_BAN];
static int numBanned = 0;

// Remote blocklist auto-update
static String updateUrl = DEFAULT_UPDATE_URL;
static uint32_t updateIntervalH = 24;
static String updateStatus = "pendiente";
static String updateEtag = "";           // validator of the list currently in flash (ETag / Last-Modified)
static uint32_t nextUpdateAt = 0;
static bool updateScheduled = false;
static uint8_t updateFailures = 0;
static bool updateBusy = false;

// Optional features (persisted in /features.cfg)
static bool featSafeSearch = false;      // force SafeSearch on Google / Bing / YouTube
static bool featBlockDoh = false;        // block known DoH/DoT resolvers so devices cannot bypass the filter

// WiFi provisioning (captive portal)
static Preferences prefs;
static DNSServer   dnsPortal;
static String      portalOpts;



// ---- Live Query Log Ring Buffer ----
struct QueryLogEntry {
  uint32_t timeMs;
  uint32_t ip;
  char domain[72];
  uint16_t qtype;
  uint8_t status; // 0=Blocked (list), 1=Blocked (custom), 2=Allowed (upstream), 3=Allowed (cache), 4=Allowed (whitelist), 5=Banned, 6=CNAME cloaked, 7=No upstream answer, 8=SafeSearch
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

// ---- Statistics: top domains + 24 h history (persisted in /stats.cfg) ----
struct TopEntry { char d[44]; uint32_t n; };
static const int TOP_N = 24;
static TopEntry topBlocked[TOP_N], topAllowed[TOP_N];
struct HourBucket { uint32_t hour, blocked, allowed; };
static const int HIST_N = 24;
static HourBucket hist[HIST_N];
static bool statsDirty = false;
static uint32_t lastStatsSaveMs = 0;

// "Space-saving" heavy-hitter counter: exact for the busiest names, approximate for the long tail
static void topHit(TopEntry* t, const char* dom) {
  int minIdx = 0;
  uint32_t minN = 0xFFFFFFFFUL;
  for (int i = 0; i < TOP_N; i++) {
    if (t[i].n && strncmp(t[i].d, dom, sizeof(t[i].d) - 1) == 0) { t[i].n++; return; }
    if (t[i].n < minN) { minN = t[i].n; minIdx = i; }
  }
  strncpy(t[minIdx].d, dom, sizeof(t[minIdx].d) - 1);
  t[minIdx].d[sizeof(t[minIdx].d) - 1] = 0;
  t[minIdx].n = minN + 1;
}

// Hours since the epoch, or 0 while NTP has not synced yet
static uint32_t nowHour() {
  time_t t = time(nullptr);
  return t > 1700000000 ? (uint32_t)(t / 3600) : 0;
}

static void statsHit(const char* dom, bool blocked) {
  if (dom && *dom) topHit(blocked ? topBlocked : topAllowed, dom);
  uint32_t h = nowHour();
  if (h) {
    HourBucket& b = hist[h % HIST_N];
    if (b.hour != h) { b.hour = h; b.blocked = 0; b.allowed = 0; }
    if (blocked) b.blocked++; else b.allowed++;
  }
  statsDirty = true;
}

static void saveStatsFile() {
  File f = LittleFS.open("/stats.cfg", "w");
  if (!f) return;
  f.printf("v1\n%lu %lu %lu %lu\n", (unsigned long)totalBlocked, (unsigned long)totalAllowed,
           (unsigned long)cacheHits, (unsigned long)totalCnameBlocked);
  for (int i = 0; i < TOP_N; i++) if (topBlocked[i].n) f.printf("B %lu %s\n", (unsigned long)topBlocked[i].n, topBlocked[i].d);
  for (int i = 0; i < TOP_N; i++) if (topAllowed[i].n) f.printf("A %lu %s\n", (unsigned long)topAllowed[i].n, topAllowed[i].d);
  for (int i = 0; i < HIST_N; i++) if (hist[i].hour) f.printf("H %lu %lu %lu\n", (unsigned long)hist[i].hour,
                                                            (unsigned long)hist[i].blocked, (unsigned long)hist[i].allowed);
  f.close();
  statsDirty = false;
  lastStatsSaveMs = millis();
}

static void loadPersistedStats() {
  File f = LittleFS.open("/stats.cfg", "r");
  if (!f) return;
  String l = f.readStringUntil('\n'); l.trim();
  if (l != "v1") { f.close(); return; }
  l = f.readStringUntil('\n');
  unsigned long a = 0, b = 0, c = 0, d = 0;
  sscanf(l.c_str(), "%lu %lu %lu %lu", &a, &b, &c, &d);
  totalBlocked = a; totalAllowed = b; cacheHits = c; totalCnameBlocked = d;
  int nb = 0, na = 0;
  while (f.available()) {
    l = f.readStringUntil('\n'); l.trim();
    if (l.length() < 5) continue;
    char kind = l[0];
    if (kind == 'H') {
      unsigned long h = 0, bb = 0, aa = 0;
      if (sscanf(l.c_str() + 2, "%lu %lu %lu", &h, &bb, &aa) == 3 && h) {
        HourBucket& hb = hist[h % HIST_N];
        hb.hour = h; hb.blocked = bb; hb.allowed = aa;
      }
    } else if (kind == 'B' || kind == 'A') {
      int sp = l.indexOf(' ', 2);
      if (sp < 0) continue;
      unsigned long n = (unsigned long)l.substring(2, sp).toInt();
      String d2 = l.substring(sp + 1);
      if (!n || !d2.length()) continue;
      TopEntry* t = (kind == 'B') ? topBlocked : topAllowed;
      int& cnt = (kind == 'B') ? nb : na;
      if (cnt >= TOP_N) continue;
      strncpy(t[cnt].d, d2.c_str(), sizeof(t[cnt].d) - 1);
      t[cnt].d[sizeof(t[cnt].d) - 1] = 0;
      t[cnt].n = n;
      cnt++;
    }
  }
  f.close();
}

static void resetStats() {
  totalBlocked = totalAllowed = cacheHits = totalCnameBlocked = 0;
  memset(topBlocked, 0, sizeof(topBlocked));
  memset(topAllowed, 0, sizeof(topAllowed));
  memset(hist, 0, sizeof(hist));
  for (int i = 0; i < numClients; i++) clients[i].blocked = clients[i].allowed = 0;
  LittleFS.remove("/stats.cfg");
  statsDirty = false;
}

// ---- Controlled restarts + reboot reason (shown in the dashboard) ----
static Preferences sysPrefs;
static String lastResetReason = "";
static uint32_t autoRebootCount = 0;

// `automatic` = the firmware restarted itself to recover (memory / WiFi); counted for the dashboard
static void safeRestart(const char* reason, bool automatic) {
  Serial.printf("[restart] %s\n", reason);
  saveStatsFile();
  sysPrefs.begin("sys", false);
  sysPrefs.putString("rr", reason);
  if (automatic) sysPrefs.putUInt("rc", sysPrefs.getUInt("rc", 0) + 1);
  sysPrefs.end();
  delay(150);
  ESP.restart();
}

static void loadResetInfo() {
  sysPrefs.begin("sys", false);
  autoRebootCount = sysPrefs.getUInt("rc", 0);
  String rr = sysPrefs.getString("rr", "");
  if (rr.length()) {
    lastResetReason = rr;
    sysPrefs.remove("rr");
  } else {
    switch (esp_reset_reason()) {
      case ESP_RST_POWERON:  lastResetReason = "encendido"; break;
      case ESP_RST_SW:       lastResetReason = "software"; break;
      case ESP_RST_PANIC:    lastResetReason = "fallo del firmware (panic)"; break;
      case ESP_RST_INT_WDT:
      case ESP_RST_TASK_WDT:
      case ESP_RST_WDT:      lastResetReason = "watchdog (cuelgue)"; autoRebootCount++; sysPrefs.putUInt("rc", autoRebootCount); break;
      case ESP_RST_BROWNOUT: lastResetReason = "tensión baja (brownout)"; break;
      default:               lastResetReason = "otro"; break;
    }
  }
  sysPrefs.end();
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
  for (int i = 0; i < numAllow; i++)
    if (allowWild[i] && wildMatch(allowDom[i].c_str(), domain)) return true;
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
  for (int i = 0; i < numCustom; i++) {
    if (customWild[i] && wildMatch(customDom[i].c_str(), domain)) {
      if (isCustomOut) *isCustomOut = true;
      return true;
    }
  }
  return false;
}

// ---------- CNAME Cloaking Detection ----------
static bool extractDnsName(const uint8_t* pkt, int len, int offset, char* out, size_t outMax) {
  int ptrs = 0;
  size_t outPos = 0;
  int curr = offset;
  while (curr < len && ptrs < 8) {
    uint8_t l = pkt[curr];
    if (l == 0) break;
    if ((l & 0xC0) == 0xC0) {
      if (curr + 1 >= len) return false;
      int next = ((l & 0x3F) << 8) | pkt[curr + 1];
      if (next >= len) return false;
      curr = next;
      ptrs++;
      continue;
    }
    curr++;
    if (outPos + l + 1 >= outMax || curr + l > len) return false;
    if (outPos > 0) out[outPos++] = '.';
    for (uint8_t k = 0; k < l; k++) out[outPos++] = tolower(pkt[curr++]);
  }
  out[outPos] = 0;
  if (outPos > 4 && strncmp(out, "www.", 4) == 0) {
    memmove(out, out + 4, outPos - 3);
  }
  return (outPos > 0);
}

static bool checkCnameCloak(const uint8_t* pkt, int len, int qend, char* cloakDomain, size_t maxLen) {
  if (len < 12 || qend >= len) return false;
  uint16_t ancount = (pkt[6] << 8) | pkt[7];
  if (ancount == 0) return false;

  int curr = qend;
  for (int a = 0; a < ancount && curr < len; a++) {
    if (curr >= len) break;
    if ((pkt[curr] & 0xC0) == 0xC0) {
      curr += 2;
    } else {
      while (curr < len && pkt[curr] != 0) {
        curr += (pkt[curr] + 1);
      }
      curr++;
    }
    if (curr + 10 > len) break;
    uint16_t rtype = ((uint16_t)pkt[curr] << 8) | pkt[curr + 1];
    uint16_t rdlen = ((uint16_t)pkt[curr + 8] << 8) | pkt[curr + 9];
    int rdata = curr + 10;
    curr = rdata + rdlen;

    if (rtype == 5) { // CNAME Record
      char target[128];
      if (extractDnsName(pkt, len, rdata, target, sizeof(target))) {
        if (!isAllowed(target) && isBlocked(target, nullptr)) {
          strncpy(cloakDomain, target, maxLen - 1);
          cloakDomain[maxLen - 1] = 0;
          return true;
        }
      }
    }
  }
  return false;
}

// ---------- Persistence ----------
// A rule is a plain domain (blocks/allows it and all its subdomains) or a wildcard pattern
// such as "*.tracker.*" or "ads?.example.com".
static bool isValidRule(const String& d) {
  if (!d.length() || d.length() > 100) return false;
  for (unsigned i = 0; i < d.length(); i++) {
    unsigned char ch = (unsigned char)d[i];
    if (!(isalnum(ch) || ch == '.' || ch == '-' || ch == '_' || ch == '*' || ch == '?')) return false;
  }
  return true;
}

static void loadCustom() {
  numCustom = 0;
  File f = LittleFS.open("/custom.txt", "r");
  if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    bool wild = hasWildcard(l.c_str());
    if (l.length() && (wild || l.indexOf('.') > 0)) {
      customDom[numCustom] = l;
      customHash[numCustom] = fnv40(l.c_str(), l.length());
      customWild[numCustom] = wild;
      numCustom++;
    }
  }
  f.close();
  listVersion++;
}

static void saveCustom() {
  File f = LittleFS.open("/custom.txt", "w");
  if (!f) return;
  for (int i = 0; i < numCustom; i++) f.println(customDom[i]);
  f.close();
}

static bool addCustom(String d, bool save = true) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  bool wild = hasWildcard(d.c_str());
  if (!isValidRule(d) || (!wild && d.indexOf('.') < 0) || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d;
  customHash[numCustom] = fnv40(d.c_str(), d.length());
  customWild[numCustom] = wild;
  numCustom++;
  listVersion++;
  if (save) saveCustom();
  return true;
}

static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) {
    if (customDom[i] == d) {
      for (int j = i; j < numCustom - 1; j++) {
        customDom[j] = customDom[j+1];
        customHash[j] = customHash[j+1];
        customWild[j] = customWild[j+1];
      }
      numCustom--;
      listVersion++;
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
    bool wild = hasWildcard(l.c_str());
    if (l.length() && (wild || l.indexOf('.') > 0)) {
      allowDom[numAllow] = l;
      allowHash[numAllow] = fnv40(l.c_str(), l.length());
      allowWild[numAllow] = wild;
      numAllow++;
    }
  }
  f.close();
  listVersion++;
}

static void saveAllow() {
  File f = LittleFS.open("/allowlist.txt", "w");
  if (!f) return;
  for (int i = 0; i < numAllow; i++) f.println(allowDom[i]);
  f.close();
}

static bool addAllow(String d, bool save = true) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  bool wild = hasWildcard(d.c_str());
  if (!isValidRule(d) || (!wild && d.indexOf('.') < 0) || numAllow >= MAX_ALLOW) return false;
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) return false;
  allowDom[numAllow] = d;
  allowHash[numAllow] = fnv40(d.c_str(), d.length());
  allowWild[numAllow] = wild;
  numAllow++;
  listVersion++;
  if (save) saveAllow();
  return true;
}

static void removeAllow(String d) {
  d.toLowerCase();
  for (int i = 0; i < numAllow; i++) {
    if (allowDom[i] == d) {
      for (int j = i; j < numAllow - 1; j++) {
        allowDom[j] = allowDom[j+1];
        allowHash[j] = allowHash[j+1];
        allowWild[j] = allowWild[j+1];
      }
      numAllow--;
      listVersion++;
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
  File f = LittleFS.open("/banned.txt", "w");
  if (!f) return;
  for (int i = 0; i < numBanned; i++) {
    IPAddress ip(bannedIP[i]);
    f.println(ip.toString());
  }
  f.close();
}

// Updates the persistent ban table (kept even for devices that are currently offline)
static void setBanned(uint32_t ip, bool ban, bool save = true) {
  int idx = -1;
  for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) { idx = i; break; }
  if (ban && idx < 0 && numBanned < MAX_BAN) bannedIP[numBanned++] = ip;
  else if (!ban && idx >= 0) bannedIP[idx] = bannedIP[--numBanned];
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) clients[i].banned = ban;
  if (save) saveBanned();
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

// Persistent alias table: names survive reboots and apply to a device the moment it shows up again
static uint32_t labelIp[MAX_CLIENTS];
static String labelName[MAX_CLIENTS];
static int numLabels = 0;

static String labelFor(uint32_t ip) {
  for (int i = 0; i < numLabels; i++) if (labelIp[i] == ip) return labelName[i];
  return String();
}

static void loadLabels() {
  numLabels = 0;
  File f = LittleFS.open("/labels.txt", "r");
  if (!f) return;
  while (f.available() && numLabels < MAX_CLIENTS) {
    String l = f.readStringUntil('\n'); l.trim();
    int sep = l.indexOf(',');
    if (sep > 0) {
      IPAddress ip;
      if (ip.fromString(l.substring(0, sep))) {
        labelIp[numLabels] = (uint32_t)ip;
        labelName[numLabels] = l.substring(sep + 1);
        numLabels++;
      }
    }
  }
  f.close();
}

static void saveLabels() {
  File f = LittleFS.open("/labels.txt", "w");
  if (!f) return;
  for (int i = 0; i < numLabels; i++) {
    IPAddress ip(labelIp[i]);
    f.print(ip.toString());
    f.print(",");
    f.println(labelName[i]);
  }
  f.close();
}

static void setLabel(uint32_t ip, String name, bool save = true) {
  name.trim();
  name.replace("\n", " ");
  name.replace("\r", " ");
  if (name.length() > 40) name = name.substring(0, 40);
  int idx = -1;
  for (int i = 0; i < numLabels; i++) if (labelIp[i] == ip) { idx = i; break; }
  if (!name.length()) {
    if (idx >= 0) {
      for (int j = idx; j < numLabels - 1; j++) { labelIp[j] = labelIp[j+1]; labelName[j] = labelName[j+1]; }
      numLabels--;
    }
  } else if (idx >= 0) {
    labelName[idx] = name;
  } else if (numLabels < MAX_CLIENTS) {
    labelIp[numLabels] = ip;
    labelName[numLabels] = name;
    numLabels++;
  }
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) clients[i].label = name;
  if (save) saveLabels();
}

static void loadFeatures() {
  File f = LittleFS.open("/features.cfg", "r");
  if (!f) return;
  while (f.available()) {
    String l = f.readStringUntil('\n'); l.trim();
    if (l == "ss=1") featSafeSearch = true;
    else if (l == "doh=1") featBlockDoh = true;
  }
  f.close();
}

static void saveFeatures() {
  File f = LittleFS.open("/features.cfg", "w");
  if (!f) return;
  f.println(featSafeSearch ? "ss=1" : "ss=0");
  f.println(featBlockDoh ? "doh=1" : "doh=0");
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
    c->label = labelFor(ip);
    getMac(ip, c->mac);
    return c;
  }
  return nullptr;
}

// ---------- DNS Core ----------
// `fullKey` receives the hash of the complete lower-case query name (cache key); the returned
// name has a leading "www." stripped because that is how the blocklists are normalised.
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend, uint64_t* fullKey) {
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
  if (fullKey) *fullKey = fnv40(out, o);
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

// NXDOMAIN (used for the Firefox/Chrome DoH canary domain)
static int buildNxdomain(int qend) {
  buf[2] = 0x81; buf[3] = 0x83;
  buf[4] = 0; buf[5] = 1;
  buf[6] = 0; buf[7] = 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  return qend;
}

// SERVFAIL so clients fail fast (or try their next DNS server) instead of waiting for a silent timeout
static int buildServfail(int qend) {
  buf[2] = 0x81; buf[3] = 0x82;
  buf[4] = 0; buf[5] = 1;
  buf[6] = 0; buf[7] = 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  return qend;
}

// Fixed IPv4 answer (SafeSearch); every other type gets an empty NOERROR answer (e.g. AAAA -> no IPv6 bypass)
static int buildAddr(int qend, uint16_t qtype, const uint8_t ip[4]) {
  buf[2] = 0x81; buf[3] = 0x80;
  buf[4] = 0; buf[5] = 1;
  buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0;
  buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t hdr[] = { 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04 };
  memcpy(buf + qend, hdr, sizeof(hdr));
  memcpy(buf + qend + sizeof(hdr), ip, 4);
  return qend + (int)sizeof(hdr) + 4;
}

// ---------- Async upstream forwarding ----------
// Queries are forwarded without blocking the main loop: each one gets a slot in a small pending
// table keyed by a random upstream id. The first (fastest, see latency EWMA) resolver is asked right
// away; if it has not answered after HEDGE_MS the second one is asked too (hedged request) and
// whichever answers first wins. After UP_TIMEOUT_MS the client gets a stale cached answer or SERVFAIL.
static const int MAX_PENDING = 16;
static const int PQ_MAX = 256;                       // max client query size we can park
static const uint32_t HEDGE_MS = 250;
static const uint32_t UP_TIMEOUT_MS = 900;
static const uint32_t LAT_SWITCH_MARGIN = 25;        // ms the 2nd resolver must beat the 1st by before they swap roles

struct Pending {
  bool used;
  bool viaWl;               // domain is whitelisted -> no CNAME-cloak check, logged as whitelist
  bool plain;               // unparsable name: just relay, no cache/log/stats
  uint8_t kind;             // 0 = client query, 1 = background refresh (prefetch / stale revalidation)
  uint8_t stage;            // 0 = first resolver asked, 1 = both asked
  bool firstIsSecondary;
  uint16_t upId;
  uint16_t cliId;
  uint16_t qtype;
  uint16_t qlen;
  uint16_t qend;
  uint16_t cport;
  uint32_t cip;
  uint32_t sentAt;
  uint64_t key;
  char domain[72];
  uint8_t q[PQ_MAX];
};
static Pending pend[MAX_PENDING];
static uint8_t rbuf[600];
static uint32_t latPri = 80, latSec = 80;            // smoothed round-trip time per resolver (ms)

static void reply(uint32_t ip, uint16_t port, int len) {
  IPAddress a(ip);
  dnsServer.beginPacket(a, port);
  dnsServer.write(buf, len);
  dnsServer.endPacket();
}

static void sendUp(bool toSecondary, const uint8_t* pkt, int len) {
  upstreamCli.beginPacket(toSecondary ? upstreamSecondary : upstreamPrimary, 53);
  upstreamCli.write(pkt, len);
  upstreamCli.endPacket();
}

static int pendingCount() {
  int n = 0;
  for (int i = 0; i < MAX_PENDING; i++) if (pend[i].used) n++;
  return n;
}

static bool queueUpstream(uint8_t kind, const uint8_t* q, int qlen, int qend, uint16_t qtype, uint64_t key,
                          const char* domain, uint32_t cip, uint16_t cport, bool viaWl, bool plain) {
  if (qlen > PQ_MAX || qlen < 12) return false;
  int slot = -1;
  for (int i = 0; i < MAX_PENDING; i++) if (!pend[i].used) { slot = i; break; }
  if (slot < 0) {   // table full: sacrifice a background refresh if there is one
    for (int i = 0; i < MAX_PENDING; i++) {
      if (pend[i].used && pend[i].kind == 1) {
        clearRefreshing(pend[i].key, pend[i].qtype);
        pend[i].used = false;
        slot = i;
        break;
      }
    }
  }
  if (slot < 0) return false;

  Pending& p = pend[slot];
  uint16_t id;
  for (;;) {        // random, unique upstream transaction id
    id = (uint16_t)esp_random();
    bool clash = false;
    for (int j = 0; j < MAX_PENDING; j++) if (pend[j].used && pend[j].upId == id) { clash = true; break; }
    if (!clash) break;
  }
  p.used = true;
  p.kind = kind;
  p.stage = 0;
  p.viaWl = viaWl;
  p.plain = plain;
  p.upId = id;
  p.cliId = ((uint16_t)q[0] << 8) | q[1];
  p.qtype = qtype;
  p.qlen = (uint16_t)qlen;
  p.qend = (uint16_t)qend;
  p.cport = cport;
  p.cip = cip;
  p.key = key;
  p.firstIsSecondary = (latSec + LAT_SWITCH_MARGIN < latPri);
  strncpy(p.domain, domain, sizeof(p.domain) - 1);
  p.domain[sizeof(p.domain) - 1] = 0;
  memcpy(p.q, q, qlen);
  p.q[0] = (uint8_t)(id >> 8);
  p.q[1] = (uint8_t)(id & 0xFF);
  p.sentAt = millis();
  sendUp(p.firstIsSecondary, p.q, qlen);
  return true;
}

static void noteLatency(const IPAddress& rip, uint32_t ms) {
  if (ms > 2000) ms = 2000;
  if (rip == upstreamPrimary) latPri = (latPri * 3 + ms) / 4;
  else if (rip == upstreamSecondary) latSec = (latSec * 3 + ms) / 4;
}

// An upstream response (already in rbuf) matched pending slot `p`
static void completePending(Pending& p, int n) {
  uint8_t rcode = rbuf[3] & 0x0F;

  if (p.kind == 1) {   // background refresh: only touch the cache, nobody is waiting for this
    char cloak[128];
    bool cloaked = blockingOn && checkCnameCloak(rbuf, n, p.qend, cloak, sizeof(cloak));
    if (cloaked) invalidateCache(p.key, p.qtype);
    else if (rcode == 0 || rcode == 3) storeCache(p.key, p.qtype, rbuf, n, p.qend);
    else clearRefreshing(p.key, p.qtype);
    return;
  }

  Dev* c = getClient(p.cip);
  memcpy(buf, rbuf, n);
  int rlen = n;
  buf[0] = (uint8_t)(p.cliId >> 8);
  buf[1] = (uint8_t)(p.cliId & 0xFF);

  if (!p.plain) {
    char cloakTarget[128];
    if (!p.viaWl && blockingOn && checkCnameCloak(buf, rlen, p.qend, cloakTarget, sizeof(cloakTarget))) {
      rlen = buildBlocked(p.qend, p.qtype);
      totalBlocked++;
      totalCnameBlocked++;
      if (c) c->blocked++;
      triggerLedBlockFlicker();
      addLog(p.cip, p.domain, p.qtype, 6); // 6 = CNAME Cloaked
      statsHit(p.domain, true);
    } else {
      storeCache(p.key, p.qtype, buf, rlen, p.qend);
      addLog(p.cip, p.domain, p.qtype, p.viaWl ? 4 : 2); // 4=Whitelist, 2=Upstream
      totalAllowed++;
      if (c) c->allowed++;
      statsHit(p.domain, false);
    }
  }
  reply(p.cip, p.cport, rlen);
}

// No resolver answered in time: serve a stale cached answer if we have one, otherwise SERVFAIL
static void failPending(Pending& p) {
  if (p.kind == 1) { clearRefreshing(p.key, p.qtype); return; }
  Dev* c = getClient(p.cip);
  int rlen = 0;
  bool nr = false;
  if (!p.plain && checkCache(p.key, p.qtype, buf, &rlen, p.cliId, p.qend, true, &nr) != CACHE_MISS) {
    if (nr) clearRefreshing(p.key, p.qtype);
    fixQuestion(buf, rlen, p.q, p.qend);
    addLog(p.cip, p.domain, p.qtype, 3);
    if (c) c->allowed++;
    statsHit(p.domain, false);
  } else {
    memcpy(buf, p.q, p.qend);
    buf[0] = (uint8_t)(p.cliId >> 8);
    buf[1] = (uint8_t)(p.cliId & 0xFF);
    rlen = buildServfail(p.qend);
    addLog(p.cip, p.domain[0] ? p.domain : "?", p.qtype, 7); // 7 = no upstream answer
  }
  reply(p.cip, p.cport, rlen);
}

// Call every loop iteration: drains upstream responses and handles hedging / timeouts
static void pollUpstream() {
  for (int guard = 0; guard < 16; guard++) {
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) break;
    IPAddress rip = upstreamCli.remoteIP();
    int n = upstreamCli.read(rbuf, sizeof(rbuf));
    if (n < 12) continue;
    if (!(rip == upstreamPrimary || rip == upstreamSecondary)) continue;   // not from a resolver we asked
    if (!(rbuf[2] & 0x80)) continue;                                        // not a response
    uint16_t id = ((uint16_t)rbuf[0] << 8) | rbuf[1];
    for (int i = 0; i < MAX_PENDING; i++) {
      if (pend[i].used && pend[i].upId == id) {
        noteLatency(rip, millis() - pend[i].sentAt);
        completePending(pend[i], n);
        pend[i].used = false;
        break;
      }
    }
  }

  uint32_t now = millis();
  for (int i = 0; i < MAX_PENDING; i++) {
    Pending& p = pend[i];
    if (!p.used) continue;
    uint32_t el = now - p.sentAt;
    if (el >= UP_TIMEOUT_MS) {
      failPending(p);
      p.used = false;
    } else if (p.stage == 0 && el >= HEDGE_MS) {
      // the first resolver is slow: penalise it and ask the other one as well
      if (p.firstIsSecondary) latSec = (latSec * 3 + HEDGE_MS * 2) / 4;
      else latPri = (latPri * 3 + HEDGE_MS * 2) / 4;
      sendUp(!p.firstIsSecondary, p.q, p.qlen);
      p.stage = 1;
    }
  }
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
    if (buf[2] & 0x80) continue;   // a response sent to our port, not a query

    uint16_t txid = ((uint16_t)buf[0] << 8) | buf[1];
    char domain[256];
    domain[0] = 0;
    uint16_t qtype = 0;
    int qend = qlen;
    uint64_t fkey = 0;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend, &fkey);
    uint32_t cipU = (uint32_t)cip;
    Dev* c = getClient(cipU);

    if (c && c->banned) {
      int rlen = buildBlocked(qend, qtype);
      totalBlocked++;
      c->blocked++;
      triggerLedBlockFlicker();
      addLog(cipU, domain, qtype, 5); // 5=Banned
      reply(cipU, cport, rlen);
      continue;
    }

    bool wl = dl && isAllowed(domain);

    if (!wl && blockingOn && dl) {
      // DoH canary: NXDOMAIN makes Firefox / Chrome fall back to the system resolver (this one)
      if (featBlockDoh && isDohCanary(domain)) {
        int rlen = buildNxdomain(qend);
        totalBlocked++;
        if (c) c->blocked++;
        triggerLedBlockFlicker();
        addLog(cipU, domain, qtype, 0);
        statsHit(domain, true);
        reply(cipU, cport, rlen);
        continue;
      }
      // SafeSearch: answer with the provider's forced-safe-search address
      uint8_t ssIp[4];
      if (featSafeSearch && safeSearchTarget(domain, ssIp)) {
        int rlen = buildAddr(qend, qtype, ssIp);
        totalAllowed++;
        if (c) c->allowed++;
        addLog(cipU, domain, qtype, 8);
        statsHit(domain, false);
        reply(cipU, cport, rlen);
        continue;
      }
      // Blocklist / custom rules / DoH endpoints
      bool isCustom = false;
      bool blocked = (featBlockDoh && isDohHost(domain)) ||
                     ((numHashes || numCustom) && isBlocked(domain, &isCustom));
      if (blocked) {
        int rlen = buildBlocked(qend, qtype);
        totalBlocked++;
        if (c) c->blocked++;
        triggerLedBlockFlicker();
        addLog(cipU, domain, qtype, isCustom ? 1 : 0);
        statsHit(domain, true);
        reply(cipU, cport, rlen);
        continue;
      }
    }

    // Cache first (fresh, or stale-while-revalidate)
    uint8_t qsave[280];
    if (dl && qend <= (int)sizeof(qsave)) {
      memcpy(qsave, buf, qend);   // the cache lookup overwrites buf with the cached response
      bool needRefresh = false;
      int rlen = 0;
      int cs = checkCache(fkey, qtype, buf, &rlen, txid, qend, true, &needRefresh);
      if (cs != CACHE_MISS) {
        fixQuestion(buf, rlen, qsave, qend);
        addLog(cipU, domain, qtype, 3); // 3=Cache
        if (wl) { totalAllowed++; if (c) c->allowed++; }
        statsHit(domain, false);
        reply(cipU, cport, rlen);
        if (needRefresh) {
          // refresh in the background with a plain query rebuilt from the saved question
          qsave[2] = 0x01; qsave[3] = 0x00;
          qsave[4] = 0; qsave[5] = 1;
          memset(qsave + 6, 0, 6);
          if (!queueUpstream(1, qsave, qend, qend, qtype, fkey, domain, 0, 0, false, false))
            clearRefreshing(fkey, qtype);
        }
        continue;
      }
    }

    // Miss: forward asynchronously (the client's own query, with a fresh upstream id)
    if (!queueUpstream(0, buf, qlen, qend, qtype, fkey, dl ? domain : "", cipU, cport, wl, dl == 0)) {
      int rlen = buildServfail(qend);
      addLog(cipU, dl ? domain : "?", qtype, 7);
      reply(cipU, cport, rlen);
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

// Top-10 of a space-saving table, as [["domain",count],...] sorted by count
static void emitTop(String& j, TopEntry* t) {
  bool used[TOP_N] = { false };
  bool first = true;
  for (int k = 0; k < 10; k++) {
    int best = -1;
    for (int i = 0; i < TOP_N; i++) if (!used[i] && t[i].n && (best < 0 || t[i].n > t[best].n)) best = i;
    if (best < 0) break;
    used[best] = true;
    if (!first) j += ",";
    first = false;
    j += "[\"" + jesc(String(t[best].d)) + "\"," + String((unsigned long)t[best].n) + "]";
  }
}

// Chunked response: the JSON is bigger than we want to hold in RAM at once
static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[32];
  snprintf(ut, sizeof(ut), "%lud %luh %lum", (unsigned long)(up/86400), (unsigned long)((up%86400)/3600), (unsigned long)((up%3600)/60));

  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "application/json", "");

  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + String((unsigned long)totalBlocked) +
             ",\"allowed\":" + String((unsigned long)totalAllowed) + ",\"cname\":" + String((unsigned long)totalCnameBlocked) +
             ",\"cacheHits\":" + String((unsigned long)cacheHits) +
             ",\"domains\":" + String((unsigned long)numHashes) + ",\"rssi\":" + WiFi.RSSI() +
             ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + String((unsigned long)ESP.getFreeHeap()) + ",\"minHeap\":" + String((unsigned long)ESP.getMinFreeHeap()) +
             ",\"maxBlock\":" + String((unsigned long)ESP.getMaxAllocHeap()) + ",\"uptime\":\"" + ut + "\"" +
             ",\"dnsPri\":\"" + upstreamPrimary.toString() + "\",\"dnsSec\":\"" + upstreamSecondary.toString() + "\"" +
             ",\"latPri\":" + String((unsigned long)latPri) + ",\"latSec\":" + String((unsigned long)latSec) +
             ",\"pend\":" + pendingCount() +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + String((unsigned long)updateIntervalH) +
             ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"lv\":" + String((unsigned long)listVersion) +
             ",\"rst\":\"" + jesc(lastResetReason) + "\",\"rstc\":" + String((unsigned long)autoRebootCount) +
             ",\"ss\":" + (featSafeSearch ? "true" : "false") + ",\"doh\":" + (featBlockDoh ? "true" : "false") +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + String((unsigned long)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0)) +
             ",\"led\":" + (ledEnabled ? "true" : "false") +
             ",\"clients\":[";

  for (int i = 0; i < numClients; i++) {
    Dev& c = clients[i];
    IPAddress ip(c.ip);
    if (i) j += ",";
    j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"label\":\"" + jesc(c.label) +
         "\",\"blocked\":" + String((unsigned long)c.blocked) + ",\"allowed\":" + String((unsigned long)c.allowed) +
         ",\"banned\":" + (c.banned ? "true" : "false") + "}";
    if (j.length() > 1200) { web.sendContent(j); j = ""; }
  }
  j += "],\"top\":{\"b\":[";
  emitTop(j, topBlocked);
  j += "],\"a\":[";
  emitTop(j, topAllowed);
  j += "]},\"hist\":[";
  uint32_t nh = nowHour();
  bool first = true;
  if (nh) {
    for (uint32_t h = nh - (HIST_N - 1); h <= nh; h++) {
      HourBucket& b = hist[h % HIST_N];
      if (b.hour != h) continue;
      if (!first) j += ",";
      first = false;
      j += "[" + String((unsigned long)h) + "," + String((unsigned long)b.blocked) + "," + String((unsigned long)b.allowed) + "]";
    }
  }
  j += "]}";
  web.sendContent(j);
  web.sendContent("");
}

// Custom block rules + whitelist, fetched only when `lv` (listVersion) changes
static void handleLists() {
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "application/json", "");
  String j = "{\"custom\":[";
  for (int i = 0; i < numCustom; i++) {
    if (i) j += ",";
    j += "\"" + jesc(customDom[i]) + "\"";
    if (j.length() > 1200) { web.sendContent(j); j = ""; }
  }
  j += "],\"whitelist\":[";
  for (int i = 0; i < numAllow; i++) {
    if (i) j += ",";
    j += "\"" + jesc(allowDom[i]) + "\"";
    if (j.length() > 1200) { web.sendContent(j); j = ""; }
  }
  j += "]}";
  web.sendContent(j);
  web.sendContent("");
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
    getClient((uint32_t)ip);
    setBanned((uint32_t)ip, !isBannedIP((uint32_t)ip));
  }
  web.send(200, "text/plain", "ok");
}

static void handleSetLabel() {
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    getClient((uint32_t)ip);
    setLabel((uint32_t)ip, web.arg("name"));
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

static void handleSetFeature() {
  String k = web.arg("k");
  bool v = web.arg("v") == "1";
  if (k == "ss") featSafeSearch = v;
  else if (k == "doh") featBlockDoh = v;
  else { web.send(400, "text/plain", "bad key"); return; }
  saveFeatures();
  clearCache();   // answers cached under the old policy must not leak through
  web.send(200, "text/plain", "ok");
}

static void handleResetStats() {
  resetStats();
  web.send(200, "text/plain", "ok");
}

// ---------- Config export / import (plain text) ----------
static void handleExport() {
  web.sendHeader("Content-Disposition", "attachment; filename=\"adblockhouse-config.txt\"");
  web.setContentLength(CONTENT_LENGTH_UNKNOWN);
  web.send(200, "text/plain", "");
  String s = "# AdBlockHouse config v1\n";
  s += "dns.primary=" + upstreamPrimary.toString() + "\n";
  s += "dns.secondary=" + upstreamSecondary.toString() + "\n";
  s += "update.url=" + updateUrl + "\n";
  s += "update.hours=" + String((unsigned long)updateIntervalH) + "\n";
  s += String("feature.safesearch=") + (featSafeSearch ? "1" : "0") + "\n";
  s += String("feature.blockdoh=") + (featBlockDoh ? "1" : "0") + "\n";
  s += String("led=") + (ledEnabled ? "1" : "0") + "\n";
  web.sendContent(s); s = "";
  for (int i = 0; i < numCustom; i++) {
    s += "block=" + customDom[i] + "\n";
    if (s.length() > 1000) { web.sendContent(s); s = ""; }
  }
  for (int i = 0; i < numAllow; i++) {
    s += "allow=" + allowDom[i] + "\n";
    if (s.length() > 1000) { web.sendContent(s); s = ""; }
  }
  for (int i = 0; i < numLabels; i++) {
    IPAddress ip(labelIp[i]);
    s += "label=" + ip.toString() + "," + labelName[i] + "\n";
    if (s.length() > 1000) { web.sendContent(s); s = ""; }
  }
  for (int i = 0; i < numBanned; i++) {
    IPAddress ip(bannedIP[i]);
    s += "ban=" + ip.toString() + "\n";
  }
  web.sendContent(s);
  web.sendContent("");
}

static void saveUpdateCfg();

static void handleImport() {
  const String& body = web.arg("plain");
  if (body.length() < 20 || body.length() > 32768 || body.indexOf("AdBlockHouse") < 0) {
    web.send(400, "text/plain", "archivo no válido");
    return;
  }
  numCustom = 0; numAllow = 0; numLabels = 0; numBanned = 0;
  for (int i = 0; i < numClients; i++) { clients[i].banned = false; clients[i].label = ""; }
  int nb = 0, na = 0;
  int pos = 0, len = body.length();
  while (pos < len) {
    int e = body.indexOf('\n', pos);
    if (e < 0) e = len;
    String l = body.substring(pos, e);
    pos = e + 1;
    l.trim();
    if (!l.length() || l[0] == '#') continue;
    int eq = l.indexOf('=');
    if (eq <= 0) continue;
    String k = l.substring(0, eq), v = l.substring(eq + 1);
    v.trim();
    IPAddress ip;
    if (k == "dns.primary") { if (ip.fromString(v)) upstreamPrimary = ip; }
    else if (k == "dns.secondary") { if (ip.fromString(v)) upstreamSecondary = ip; }
    else if (k == "update.url") { if (v != updateUrl) { updateUrl = v; updateEtag = ""; LittleFS.remove("/update.etag"); } }
    else if (k == "update.hours") { long h = v.toInt(); if (h >= 1 && h <= 720) updateIntervalH = (uint32_t)h; }
    else if (k == "feature.safesearch") featSafeSearch = (v == "1");
    else if (k == "feature.blockdoh") featBlockDoh = (v == "1");
    else if (k == "led") { ledEnabled = (v == "1"); }
    else if (k == "block") { if (addCustom(v, false)) nb++; }
    else if (k == "allow") { if (addAllow(v, false)) na++; }
    else if (k == "label") {
      int c = v.indexOf(',');
      if (c > 0 && ip.fromString(v.substring(0, c))) setLabel((uint32_t)ip, v.substring(c + 1), false);
    }
    else if (k == "ban") { if (ip.fromString(v)) setBanned((uint32_t)ip, true, false); }
  }
  saveCustom(); saveAllow(); saveLabels(); saveBanned();
  saveDnsCfg(); saveFeatures(); saveLedCfg();
  saveUpdateCfg();
  updateScheduled = false;
  listVersion++;
  clearCache();
  updateLed(false);
  web.send(200, "text/plain", "ok: " + String(nb) + " bloqueos, " + String(na) + " permitidos");
}

// ---------- Blocklist Swap & safe update ----------
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildCheckpoints();
}

static void saveUpdateEtag() {
  File f = LittleFS.open("/update.etag", "w");
  if (!f) return;
  f.print(updateEtag);
  f.close();
}

static void clearUpdateEtag() {
  updateEtag = "";
  LittleFS.remove("/update.etag");
}

// Atomically swaps /blocklist.new into place. The window with no list is a few milliseconds
// (boot recovers /blocklist.new if power is lost inside it).
static bool activateNewBlocklist() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  numCheckpoints = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  bool ok = LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  reopenBlocklist();
  clearCache();
  return ok;
}

// A real list: whole 5-byte entries, enough of them, and sorted (the lookup is a binary search)
static bool validateBlocklistFile(const char* path, uint32_t* entriesOut, String* why) {
  File f = LittleFS.open(path, "r");
  if (!f) { *why = "no se pudo leer"; return false; }
  size_t sz = f.size();
  if (sz % HASH_BYTES) { f.close(); *why = "tamaño no múltiplo de 5 (¿es un blocklist.bin?)"; return false; }
  uint32_t n = sz / HASH_BYTES;
  if (n < MIN_LIST_ENTRIES) { f.close(); *why = "lista demasiado pequeña (" + String((unsigned long)n) + " entradas)"; return false; }
  uint8_t b[1020];
  uint64_t prev = 0;
  bool first = true;
  while (f.available()) {
    esp_task_wdt_reset();
    int r = f.read(b, sizeof(b));
    if (r <= 0 || (r % HASH_BYTES)) break;
    for (int o = 0; o < r; o += HASH_BYTES) {
      uint64_t v = 0;
      for (int k = 0; k < HASH_BYTES; k++) v |= ((uint64_t)b[o + k]) << (8 * k);
      if (!first && v < prev) { f.close(); *why = "lista sin ordenar"; return false; }
      prev = v;
      first = false;
    }
    handleDns();
    pollUpstream();
  }
  f.close();
  *entriesOut = n;
  return true;
}

static bool upOk = false;
static bool upFail = false;
static bool upForce = false;
static String upErr;
static File upFile;

static void handleUploadDone() {
  web.send(upOk ? 200 : 400, "text/plain", upOk ? String("ok") : String("rechazada: ") + upErr);
}

static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START: {
      upOk = false; upFail = false; upErr = "";
      upForce = web.arg("force") == "1";
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new");
      int64_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
      int64_t need = (int64_t)web.clientContentLength() + FS_MARGIN;
      if (upForce) {
        // forced replacement: the current list is dropped to make room (only if the new one can fit at all)
        if (need > total - (used - (int64_t)numHashes * HASH_BYTES)) { upFail = true; upErr = "no cabe en la memoria"; break; }
        if (blocklist) blocklist.close();
        numHashes = 0; numCheckpoints = 0;
        LittleFS.remove(BLOCKLIST_PATH);
      } else if (need > total - used) {
        upFail = true;
        upErr = "no cabe junto a la lista actual; usa «reemplazo forzado»";
        break;
      }
      upFile = LittleFS.open("/blocklist.new", "w");
      if (!upFile) { upFail = true; upErr = "no se pudo crear el archivo"; }
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    }
    case UPLOAD_FILE_WRITE:
      esp_task_wdt_reset();
      if (!upFail && upFile && upFile.write(u.buf, u.currentSize) != u.currentSize) {
        upFail = true; upErr = "memoria llena";
      }
      break;
    case UPLOAD_FILE_END: {
      if (upFile) upFile.close();
      uint32_t n = 0;
      if (!upFail) {
        String why;
        if (!validateBlocklistFile("/blocklist.new", &n, &why)) { upFail = true; upErr = why; }
      }
      if (upFail) {
        LittleFS.remove("/blocklist.new");
        if (upForce) reopenBlocklist();
      } else {
        upOk = activateNewBlocklist();
        if (!upOk) upErr = "no se pudo activar la lista";
        else { clearUpdateEtag(); updateStatus = "manual: " + String((unsigned long)numHashes) + " dominios"; }
      }
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", (unsigned)numHashes);
      break;
    }
    case UPLOAD_FILE_ABORTED:
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new");
      if (upForce) reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// Remote blocklist auto-update
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w");
  if (!f) return;
  f.println(updateUrl);
  f.println(updateIntervalH);
  f.close();
}

// No file -> pre-configured default URL. A saved empty URL means "updates disabled".
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r");
  if (f) {
    updateUrl = f.readStringUntil('\n'); updateUrl.trim();
    String iv = f.readStringUntil('\n'); iv.trim();
    if (iv.length()) updateIntervalH = iv.toInt();
    f.close();
  }
  if (updateIntervalH < 1) updateIntervalH = 1;
  if (updateIntervalH > 720) updateIntervalH = 720;
  File e = LittleFS.open("/update.etag", "r");
  if (e) { updateEtag = e.readString(); updateEtag.trim(); e.close(); }
}

enum { UPD_OK = 0, UPD_UNCHANGED, UPD_RETRY, UPD_PERMANENT };

// Safe download. Rules:
//  - conditional GET (If-None-Match): nothing to do when the list did not change;
//  - size / room validated from Content-Length BEFORE touching the current list;
//  - if the new file fits next to the old one, the old list stays active until the new one is complete;
//  - otherwise (flash too small for two copies) the old list is dropped only after the server
//    answered correctly, and only entries that pass the sorted-order check are written, so even an
//    interrupted download leaves a valid (partial) list instead of garbage;
//  - DNS keeps being served while downloading.
static int doFetchBlocklist(const String& url, bool force) {
  if (!url.length()) { updateStatus = "sin URL"; return UPD_PERMANENT; }
  if (WiFi.status() != WL_CONNECTED) { updateStatus = "sin WiFi"; return UPD_RETRY; }
  if (ESP.getMaxAllocHeap() < 40000) { updateStatus = "memoria insuficiente para TLS"; return UPD_RETRY; }
  Serial.printf("[remote] GET %s\n", url.c_str());

  WiFiClientSecure cs; cs.setInsecure();
  WiFiClient cl;
  HTTPClient http;
  http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  const char* collect[] = { "ETag" };
  http.collectHeaders(collect, 1);
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return UPD_RETRY; }
  if (!force && updateEtag.length() && numHashes) http.addHeader("If-None-Match", updateEtag);

  esp_task_wdt_reset();
  int code = http.GET();
  esp_task_wdt_reset();
  if (code == 304) { http.end(); updateStatus = "sin cambios"; return UPD_UNCHANGED; }
  if (code != HTTP_CODE_OK) {
    http.end();
    updateStatus = code < 0 ? String("error de conexión (") + http.errorToString(code) + ")" : "HTTP " + String(code);
    return (code >= 400 && code < 500 && code != 429) ? UPD_PERMANENT : UPD_RETRY;
  }

  int len = http.getSize();
  String newEtag = http.header("ETag");
  if (len <= 0 || (len % HASH_BYTES) || (len / HASH_BYTES) < (int)MIN_LIST_ENTRIES) {
    http.end();
    updateStatus = "archivo remoto no válido (" + String(len) + " B)";
    return UPD_PERMANENT;
  }

  LittleFS.remove("/blocklist.new");   // stale leftovers must not count as "used"
  int64_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
  int64_t oldSize = (int64_t)numHashes * HASH_BYTES;
  bool sideBySide = ((int64_t)len + FS_MARGIN <= total - used);
  if (!sideBySide && (int64_t)len + FS_MARGIN > total - (used - oldSize)) {
    http.end();
    updateStatus = "no cabe en la memoria (" + String(len) + " B)";
    return UPD_PERMANENT;
  }

  if (!sideBySide) {   // in-place: the old list goes only now that the server has answered correctly
    if (blocklist) blocklist.close();
    numHashes = 0; numCheckpoints = 0;
    LittleFS.remove(BLOCKLIST_PATH);
  }
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) {
    http.end();
    if (!sideBySide) reopenBlocklist();
    updateStatus = "no se pudo crear el archivo";
    return UPD_RETRY;
  }

  WiFiClient* stream = http.getStreamPtr();
  uint8_t b[1024];
  size_t have = 0, got = 0, wrote = 0;
  uint64_t prev = 0;
  bool first = true, bad = false, wfail = false;
  uint32_t idle = millis();
  while ((http.connected() || stream->available()) && got < (size_t)len) {
    esp_task_wdt_reset();
    size_t avail = stream->available();
    if (!avail) {
      if (millis() - idle > 15000) break;
      handleDns(); pollUpstream();
      delay(2);
      continue;
    }
    size_t want = sizeof(b) - have;
    if (want > avail) want = avail;
    if (want > (size_t)len - got) want = (size_t)len - got;
    int n = stream->readBytes(b + have, want);
    if (n <= 0) continue;
    got += n; have += n; idle = millis();
    size_t whole = have - (have % HASH_BYTES);
    for (size_t o = 0; o < whole; o += HASH_BYTES) {
      uint64_t v = 0;
      for (int k = 0; k < HASH_BYTES; k++) v |= ((uint64_t)b[o + k]) << (8 * k);
      if (!first && v < prev) { bad = true; whole = o; break; }
      prev = v; first = false;
    }
    if (whole) {
      if (f.write(b, whole) != whole) wfail = true;
      wrote += whole;
    }
    if (bad || wfail) break;
    memmove(b, b + whole, have - whole);
    have -= whole;
    handleDns(); pollUpstream();
  }
  f.close();
  http.end();

  uint32_t entries = wrote / HASH_BYTES;
  bool complete = (got == (size_t)len) && !bad && !wfail && have == 0;

  if (complete) {
    if (!activateNewBlocklist()) { updateStatus = "no se pudo activar la lista"; return UPD_RETRY; }
    updateEtag = newEtag;
    if (updateEtag.length()) saveUpdateEtag(); else clearUpdateEtag();
    updateStatus = "actualizada: " + String((unsigned long)numHashes) + " dominios";
    return UPD_OK;
  }

  String why = bad ? "datos corruptos" : wfail ? "memoria llena" : "descarga interrumpida";
  clearUpdateEtag();   // whatever is in flash is not the server's current version any more
  if (sideBySide) {
    LittleFS.remove("/blocklist.new");
    updateStatus = why + ": se conserva la lista actual";
  } else if (entries >= MIN_LIST_ENTRIES) {
    activateNewBlocklist();
    updateStatus = why + ": lista parcial de " + String((unsigned long)numHashes) + " dominios, reintentando";
  } else {
    LittleFS.remove("/blocklist.new");
    reopenBlocklist();
    updateStatus = why + ": sin lista, reintentando";
  }
  return bad ? UPD_PERMANENT : UPD_RETRY;
}

static int fetchBlocklist(const String& url, bool force) {
  updateBusy = true;
  int rc = doFetchBlocklist(url, force);
  updateBusy = false;
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return rc;
}

// Retry backoff after transient failures: 5 min -> 15 min -> 60 min, then the normal interval
static void scheduleNextUpdate(int rc) {
  static const uint32_t backoffMin[3] = { 5, 15, 60 };
  uint32_t delayMs = updateIntervalH * 3600000UL;
  if (rc == UPD_RETRY) {
    if (updateFailures < 3) delayMs = backoffMin[updateFailures] * 60000UL;
    if (updateFailures < 255) updateFailures++;
  } else {
    updateFailures = 0;
  }
  nextUpdateAt = millis() + delayMs;
  updateScheduled = true;
}

// Firmware OTA
static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); safeRestart("actualización OTA", false); }
}

static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  esp_task_wdt_reset();
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

// ---------- Watchdog / health ----------
static uint32_t lastHealthMs = 0, lowMemCount = 0, wifiDownSince = 0, lastReconnectMs = 0;
static bool wifiWasDown = false;

static void healthCheck() {
  uint32_t now = millis();
  if (now - lastHealthMs < 5000) return;
  lastHealthMs = now;

  // memory: 6 consecutive bad samples (30 s) -> controlled restart. Skipped during TLS downloads.
  if (!updateBusy && (ESP.getFreeHeap() < LOWMEM_FREE_BYTES || ESP.getMaxAllocHeap() < LOWMEM_BLOCK_BYTES)) {
    if (++lowMemCount >= 6) safeRestart("memoria baja", true);
  } else {
    lowMemCount = 0;
  }

  if (WiFi.status() == WL_CONNECTED) {
    wifiWasDown = false;
  } else {
    if (!wifiWasDown) { wifiWasDown = true; wifiDownSince = now; }
    uint32_t down = now - wifiDownSince;
    if (down > 300000UL) safeRestart("WiFi caído", true);
    if (down > 20000UL && now - lastReconnectMs > 30000UL) { lastReconnectMs = now; WiFi.reconnect(); }
  }

  if (statsDirty && now - lastStatsSaveMs > 1800000UL) saveStatsFile();
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
  WiFi.setAutoReconnect(true);
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
  safeRestart("manual", false);
}

static void startConfigPortal() {
  int n = WiFi.scanNetworks();
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + jesc(WiFi.SSID(i)) + "'>";
  const char* ap = "AdBlock-House";
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
    updateLed(true);
    delay(2);
  }
}

void setup() {
  pinMode(LED_PIN, OUTPUT);
  loadLedCfg();
  updateLed(false);

  Serial.begin(115200);
  delay(300);
  Serial.println("\n[c3-adblock-pro] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  loadResetInfo();
  Serial.printf("reset reason: %s\n", lastResetReason.c_str());

  // power lost during a list swap: finish it
  if (!LittleFS.exists(BLOCKLIST_PATH) && LittleFS.exists("/blocklist.new")) {
    LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
    Serial.println("recovered /blocklist.new");
  }

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
  loadFeatures();
  loadPersistedStats();
  if (!numHashes) { updateEtag = ""; }   // an ETag only makes sense while its list is in flash

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

  configTime(0, 0, "pool.ntp.org", "time.google.com");   // wall clock for the 24 h chart

  dnsServer.begin(DNS_PORT);
  upstreamCli.begin(0);

  // Web Endpoints
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/lists.json", handleLists);
  web.on("/export.txt", handleExport);
  web.on("/importcfg", HTTP_POST, handleImport);
  web.on("/setfeature", handleSetFeature);
  web.on("/resetstats", handleResetStats);
  web.on("/log.json", handleLog);
  web.on("/ban", handleBan);
  web.on("/setlabel", handleSetLabel);
  web.on("/setupstream", handleSetUpstream);
  web.on("/setled", []() {
    if (web.hasArg("en")) {
      ledEnabled = (web.arg("en") == "1" || web.arg("en") == "true");
      saveLedCfg();
      updateLed(false);
    }
    web.send(200, "text/plain", ledEnabled ? "1" : "0");
  });
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
    safeRestart("manual", false);
  });
  web.on("/forgetwifi", []() {
    web.send(200, "text/plain", "cleared — rebooting");
    prefs.begin("wifi", false); prefs.clear(); prefs.end();
    delay(500);
    safeRestart("manual", false);
  });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);
  web.on("/fetchnow", []() {
    int rc = fetchBlocklist(updateUrl, true);
    scheduleNextUpdate(rc);
    web.send(200, "text/plain", updateStatus);
  });
  web.on("/setupdate", []() {
    if (web.hasArg("u")) {
      String u = web.arg("u"); u.trim();
      if (u != updateUrl) { updateUrl = u; clearUpdateEtag(); }
    }
    if (web.hasArg("h")) {
      updateIntervalH = web.arg("h").toInt();
      if (updateIntervalH < 1) updateIntervalH = 1;
      if (updateIntervalH > 720) updateIntervalH = 720;
    }
    saveUpdateCfg();
    updateScheduled = false;
    updateStatus = updateUrl.length() ? "pendiente" : "desactivada";
    web.send(200, "text/plain", "ok");
  });

  web.begin();
  ArduinoOTA.setHostname("c3adblock");
  ArduinoOTA.begin();
  Serial.println("Ready: DNS :53 + Dashboard :80 + RAM Cache + Checkpoint Index");

  // Task watchdog: the loop task must check in; a hang restarts the device
  esp_task_wdt_init(WDT_TIMEOUT_S, true);
  esp_task_wdt_add(NULL);
}

void loop() {
  esp_task_wdt_reset();
  updateLed(false);
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  pollUpstream();

  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) {
    blockingOn = true;
    resumeAt = 0;
  }

  if (updateUrl.length() && WiFi.status() == WL_CONNECTED) {
    uint32_t now = millis();
    if (!updateScheduled) {
      nextUpdateAt = now + (numHashes ? 120000UL : 20000UL);
      updateScheduled = true;
    } else if ((int32_t)(now - nextUpdateAt) >= 0) {
      int rc = fetchBlocklist(updateUrl, false);
      scheduleNextUpdate(rc);
    }
  }

  healthCheck();

  if (!busy && pendingCount() == 0) delay(1);
}
