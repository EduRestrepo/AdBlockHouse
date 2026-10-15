#pragma once
// Pure helpers (no Arduino/ESP dependencies): wildcard rule matching, DNS packet
// TTL walking, known DoH endpoints and SafeSearch redirect targets.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ---- Wildcard rules: '*' = any run of characters, '?' = exactly one character ----
// Matches against the whole (lower-case, "www."-stripped) domain name.
static inline bool wildMatch(const char* pat, const char* s) {
  const char* star = nullptr;
  const char* ss = s;
  while (*s) {
    if (*pat == '*') { star = pat++; ss = s; }
    else if (*pat == '?' || *pat == *s) { pat++; s++; }
    else if (star) { pat = star + 1; s = ++ss; }
    else return false;
  }
  while (*pat == '*') pat++;
  return *pat == 0;
}

static inline bool hasWildcard(const char* s) {
  return strchr(s, '*') != nullptr || strchr(s, '?') != nullptr;
}

// true when `d` equals `base` or is a subdomain of it
static inline bool endsWithDomain(const char* d, const char* base) {
  size_t dl = strlen(d), bl = strlen(base);
  if (dl < bl) return false;
  if (strcmp(d + dl - bl, base) != 0) return false;
  return dl == bl || d[dl - bl - 1] == '.';
}

// ---- DNS-over-HTTPS / DNS-over-TLS bypass prevention ----
static const char* const DOH_HOSTS[] = {
  "dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one",
  "dns.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com",
  "dns.adguard.com", "dns.adguard-dns.com", "doh.cleanbrowsing.org", "dns.nextdns.io",
  "dns.sb", "doh.libredns.gr", "dns.alidns.com", "doh.pub", "dot.pub",
  "dns.twnic.tw", "doh.mullvad.net", "dns.mullvad.net", "doh.appliedprivacy.net",
  "dns.digitale-gesellschaft.ch", "doh.dnslify.com", "dns.controld.com",
};

static inline bool isDohHost(const char* d) {
  for (size_t i = 0; i < sizeof(DOH_HOSTS) / sizeof(DOH_HOSTS[0]); i++)
    if (endsWithDomain(d, DOH_HOSTS[i])) return true;
  return false;
}

// Firefox (and Chrome's auto mode) disable DoH when this name answers NXDOMAIN
static inline bool isDohCanary(const char* d) {
  return strcmp(d, "use-application-dns.net") == 0;
}

// ---- SafeSearch: fixed addresses of the providers' "forced safe search" endpoints ----
// `d` must be lower-case and already stripped of a leading "www.".
static inline bool safeSearchTarget(const char* d, uint8_t ip[4]) {
  static const uint8_t GOOGLE[4] = {216, 239, 38, 120};  // forcesafesearch.google.com / restrict.youtube.com
  static const uint8_t BING[4]   = {204, 79, 197, 220};  // strict.bing.com
  bool google = false;
  if (strncmp(d, "google.", 7) == 0) {
    int dots = 0;
    for (const char* p = d; *p; p++) if (*p == '.') dots++;
    google = (dots <= 2 && strlen(d) <= 14);              // google.com, google.es, google.co.uk, google.com.co ...
  } else if (!strcmp(d, "youtube.com") || !strcmp(d, "m.youtube.com") ||
             !strcmp(d, "youtubei.googleapis.com") || !strcmp(d, "youtube.googleapis.com") ||
             !strcmp(d, "youtube-nocookie.com")) {
    google = true;
  }
  if (google) { memcpy(ip, GOOGLE, 4); return true; }
  if (!strcmp(d, "bing.com")) { memcpy(ip, BING, 4); return true; }
  return false;
}

// ---- DNS wire-format helpers ----
// Returns the offset just after the (possibly compressed) name at `off`, or -1.
static inline int dnsSkipName(const uint8_t* p, int len, int off) {
  while (off >= 0 && off < len) {
    uint8_t l = p[off];
    if (l == 0) return off + 1;
    if ((l & 0xC0) == 0xC0) return (off + 2 <= len) ? off + 2 : -1;
    off += l + 1;
  }
  return -1;
}

// Walks every resource record after the question section (qend = end of question).
//  - minOut   : receives the smallest TTL among ANSWER records (0xFFFFFFFF if none)
//  - rewrite  : when true, every TTL (except the EDNS OPT pseudo-record) is capped to newTtl
// Returns false if the packet is malformed.
static inline bool dnsWalkTtls(uint8_t* p, int len, int qend, uint32_t* minOut,
                               bool rewrite, uint32_t newTtl) {
  if (len < 12 || qend < 12 || qend > len) return false;
  uint16_t an = ((uint16_t)p[6] << 8) | p[7];
  uint16_t ns = ((uint16_t)p[8] << 8) | p[9];
  uint16_t ar = ((uint16_t)p[10] << 8) | p[11];
  int total = (int)an + (int)ns + (int)ar;
  int off = qend;
  uint32_t mn = 0xFFFFFFFFUL;
  for (int i = 0; i < total; i++) {
    off = dnsSkipName(p, len, off);
    if (off < 0 || off + 10 > len) return false;
    uint16_t type = ((uint16_t)p[off] << 8) | p[off + 1];
    uint16_t rdlen = ((uint16_t)p[off + 8] << 8) | p[off + 9];
    if (type != 41) {  // 41 = OPT: its "TTL" field carries flags, not a lifetime
      uint32_t ttl = ((uint32_t)p[off + 4] << 24) | ((uint32_t)p[off + 5] << 16) |
                     ((uint32_t)p[off + 6] << 8)  |  (uint32_t)p[off + 7];
      if (i < (int)an && ttl < mn) mn = ttl;
      if (rewrite && ttl > newTtl) {
        p[off + 4] = (uint8_t)(newTtl >> 24);
        p[off + 5] = (uint8_t)(newTtl >> 16);
        p[off + 6] = (uint8_t)(newTtl >> 8);
        p[off + 7] = (uint8_t)(newTtl);
      }
    }
    off += 10 + rdlen;
    if (off > len) return false;
  }
  if (minOut) *minOut = mn;
  return true;
}
