/* hvwatch_fast.c — lucky-boot scanner with FAST 2MB-chunk reads.
 *
 * Same SVM-cluster + plaintext-code detection as hvwatch.c, but the sweep reads
 * 2 MB per kernel_copyout (one syscall per chunk) instead of 4 KB per call,
 * which was throttling us to ~2.8 MB/s. A chunk that returns -1 (contains a
 * not-present page) falls back to 4 KB pages so nothing is missed.
 *
 * Dump target /mnt/usb0/hvwatch/, verdict RESULT.txt, early-exit on first
 * confirmed cluster, NOT-LUCKY stop at 0x4c000000 with repeated toasts.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <sys/stat.h>
#include <stdarg.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

int sceKernelOpenEventFlag(void *, const char *);
int sceKernelNotifySystemSuspendStart(void);
int sceKernelSetEventFlag(void *, int);
int sceKernelCloseEventFlag(void *);

#define PAGE            4096u
#define BIGCHUNK        0x200000ull     /* 2 MB per kernel_copyout */
#define MIN_START       0x7d00000ull    /* 125 MB */
#define CLUSTER_WINDOW  64u
#define TABLE_WORDS     8u
#define MAX_DUMPS       512u
#define NOT_LUCKY_THRESHOLD 0x4c000000ull

static int g_logfd = -1;
static unsigned char page[PAGE];
static unsigned char tmask[PAGE];
static unsigned char big[BIGCHUNK];
static char b[256];

static void logline(const char *m) {
  if (g_logfd < 0) return;
  write(g_logfd, m, strlen(m));
  write(g_logfd, "\n", 1);
  fsync(g_logfd);
}

int sceKernelSendNotificationRequest(int, void*, size_t, int);
typedef struct { char pad[45]; char msg[3075]; } notif_req_t;
static void notify(const char *fmt, ...) {
  notif_req_t req;
  va_list ap;
  memset(&req, 0, sizeof req);
  va_start(ap, fmt);
  vsnprintf(req.msg, sizeof req.msg, fmt, ap);
  va_end(ap);
  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
}

static inline uint16_t le16(const unsigned char *p) {
  return (uint16_t)(p[0] | (p[1] << 8));
}

/* ---------------- x86-64 length decoder (unchanged from hvwatch.c) -------- */
static int has_modrm(int map, unsigned char op) {
  if (map == 2 || map == 3) return 1;
  if (map == 0) {
    switch (op) {
      case 0x00: case 0x01: case 0x02: case 0x03:
      case 0x08: case 0x09: case 0x0A: case 0x0B:
      case 0x10: case 0x11: case 0x12: case 0x13:
      case 0x18: case 0x19: case 0x1A: case 0x1B:
      case 0x20: case 0x21: case 0x22: case 0x23:
      case 0x28: case 0x29: case 0x2A: case 0x2B:
      case 0x30: case 0x31: case 0x32: case 0x33:
      case 0x38: case 0x39: case 0x3A: case 0x3B:
      case 0x63: case 0x69: case 0x6B:
      case 0x80: case 0x81: case 0x83:
      case 0x84: case 0x85: case 0x86: case 0x87:
      case 0x88: case 0x89: case 0x8A: case 0x8B:
      case 0x8C: case 0x8D: case 0x8E: case 0x8F:
      case 0xC0: case 0xC1: case 0xC6: case 0xC7:
      case 0xD0: case 0xD1: case 0xD2: case 0xD3:
      case 0xD8: case 0xD9: case 0xDA: case 0xDB:
      case 0xDC: case 0xDD: case 0xDE: case 0xDF:
      case 0xF6: case 0xF7: case 0xFE: case 0xFF:
        return 1;
      default: return 0;
    }
  }
  switch (op) {
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:
    case 0x16: case 0x17: case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x1C: case 0x1D: case 0x1E: case 0x1F:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C: case 0x2D:
    case 0x2E: case 0x2F:
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
    case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
    case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
    case 0x66: case 0x67: case 0x68: case 0x69: case 0x6A: case 0x6B:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76:
    case 0x78: case 0x79:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
    case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xA3: case 0xA4: case 0xA5:
    case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5:
    case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
    case 0xC0: case 0xC1: case 0xC2: case 0xC3: case 0xC4: case 0xC5:
    case 0xC6: case 0xC7:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5:
    case 0xD6: case 0xD7: case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
    case 0xE6: case 0xE7: case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF0: case 0xF1: case 0xF2: case 0xF3: case 0xF4: case 0xF5:
    case 0xF6: case 0xF7: case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD: case 0xFE:
      return 1;
    default: return 0;
  }
}

static int x86_len(const unsigned char *p, int n) {
  const unsigned char *bq = p;
  const unsigned char *e = p + n;
  unsigned char c;
  int rexw = 0, rexb = 0, op66 = 0;

  for (;;) {
    if (bq >= e) return 0;
    c = *bq;
    if (c == 0x66) { op66 = 1; bq++; continue; }
    if (c == 0x67 || c == 0xF0 || c == 0xF2 || c == 0xF3 ||
        c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 ||
        c == 0x64 || c == 0x65) { bq++; continue; }
    if (c >= 0x40 && c <= 0x4F) { if (c & 8) rexw = 1; if (c & 1) rexb = 1; bq++; continue; }
    break;
  }
  if (bq >= e) return 0;
  c = *bq++;

  int map = 0;
  if (c == 0x0F) {
    if (bq >= e) return 0;
    c = *bq++;
    if (c == 0x38) { map = 2; if (bq >= e) return 0; c = *bq++; }
    else if (c == 0x3A) { map = 3; if (bq >= e) return 0; c = *bq++; }
    else map = 1;
  }

  if (map == 0 && (c == 0x62 || c == 0xC4 || c == 0xC5)) return 0;

  int imm = 0;
  if (!has_modrm(map, c)) {
    if (map == 0) {
      switch (c) {
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
        case 0xA8: case 0xCD: case 0xD4: case 0xD5:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xEB:
        case 0xE4: case 0xE5: case 0xE6: case 0xE7:
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5:
        case 0xB6: case 0xB7:
          imm = 1; break;
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
        case 0xA9:
        case 0xE8: case 0xE9:
          imm = op66 ? 2 : 4; break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD:
        case 0xBE: case 0xBF:
          imm = rexw ? 8 : (op66 ? 2 : 4); break;
        case 0xC2: case 0xCA:
          imm = 2; break;
        case 0xC8:
          imm = 3; break;
        case 0xEA:
          imm = 7; break;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3:
          imm = rexw ? 8 : (op66 ? 2 : 4); break;
        default: imm = 0; break;
      }
    } else if (map == 1) {
      switch (c) {
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
          imm = op66 ? 2 : 4; break;
        default: imm = 0; break;
      }
    }
    if (bq + imm > e) return 0;
    return (int)(bq + imm - p);
  }

  if (bq >= e) return 0;
  unsigned char modrm = *bq++;
  int mod = modrm >> 6;
  int rm  = modrm & 7;
  int sib_base = -1;

  if (mod != 3 && rm == 4) {
    if (bq >= e) return 0;
    sib_base = *bq & 7;
    bq++;
  }
  if (mod == 1) {
    if (bq >= e) return 0;
    bq++;
  } else if (mod == 2) {
    if (bq + 4 > e) return 0;
    bq += 4;
  } else if (mod == 0) {
    if (rm == 5 && !rexb) {
      if (bq + 4 > e) return 0;
      bq += 4;
    } else if (sib_base == 5 && !rexb) {
      if (bq + 4 > e) return 0;
      bq += 4;
    }
  }

  imm = 0;
  if (map == 2) {
    imm = 0;
  } else if (map == 3) {
    imm = 1;
  } else if (map == 0) {
    switch (c) {
      case 0x69: imm = op66 ? 2 : 4; break;
      case 0x6B: case 0x80: case 0x83: case 0xC0: case 0xC1: case 0xC6:
        imm = 1; break;
      case 0x81: case 0xC7: imm = op66 ? 2 : 4; break;
      case 0xF6: if (((modrm >> 3) & 7) < 2) imm = 1; break;
      case 0xF7: if (((modrm >> 3) & 7) < 2) imm = (op66 ? 2 : 4); break;
      default: imm = 0; break;
    }
  } else {
    switch (c) {
      case 0x70: case 0x71: case 0x72: case 0x73:
      case 0xA4: case 0xAC: case 0xBA:
      case 0xC2: case 0xC4: case 0xC5: case 0xC6:
        imm = 1; break;
      default: imm = 0; break;
    }
  }
  if (bq + imm > e) return 0;
  return (int)(bq + imm - p);
}

static void detect_tables(const unsigned char *p, int n, unsigned char *mask) {
  int run_start = 0, run_words = 0;
  for (int w = 0; w + 4 <= n; w += 2) {
    int16_t d = (int16_t)(le16(p + w + 2) - le16(p + w));
    if (d == 2 || d == -2) {
      if (run_words == 0) run_start = w;
      run_words++;
    } else {
      if (run_words + 1 >= (int)TABLE_WORDS) {
        int s = run_start;
        int e2 = run_start + (run_words + 1) * 2;
        if (e2 > n) e2 = n;
        for (int k = s; k < e2; k++) mask[k] = 1;
      }
      run_words = 0;
    }
  }
  if (run_words + 1 >= (int)TABLE_WORDS) {
    int s = run_start;
    int e2 = run_start + (run_words + 1) * 2;
    if (e2 > n) e2 = n;
    for (int k = s; k < e2; k++) mask[k] = 1;
  }
}

static int scan_page(const unsigned char *buf, int n, const unsigned char *mask,
                     uint32_t *cluster_off) {
  for (int anchor = 0; anchor < 16; anchor++) {
    int i = anchor;
    int last_svm = -1;
    while (i + 3 <= n) {
      int l = x86_len(buf + i, n - i);
      if (l <= 0) { i += 1; continue; }
      if (l == 3 && buf[i] == 0x0F && buf[i + 1] == 0x01 &&
          (buf[i + 2] & 0xF8) == 0xD8 && !mask[i]) {
        if (last_svm >= 0 && (i - last_svm) <= (int)CLUSTER_WINDOW) {
          *cluster_off = (uint32_t)last_svm;
          return 1;
        }
        last_svm = i;
      }
      i += l;
    }
  }
  return 0;
}

static int looks_like_code(const unsigned char *p, int n) {
  unsigned hist[256] = {0};
  int distinct = 0;
  for (int i = 0; i < n; i++) hist[p[i]]++;
  for (int i = 0; i < 256; i++) if (hist[i]) distinct++;
  if (distinct >= 220) return 0;
  static const unsigned char pro[9] = {0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53};
  for (int i = 0; i + 9 <= n; i++) if (memcmp(p + i, pro, 9) == 0) return 1;
  for (int i = 0; i + 2 <= n; i++) if (p[i] == 0x6c && p[i+1] == 0x8a) return 1;
  return 0;
}

static void notlucky_stop(void) {
  int rf = open("/mnt/usb0/hvwatch/RESULT.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (rf >= 0) { write(rf, "dumps=0\nNOT-LUCKY\n", 18); fsync(rf); close(rf); }
  logline("NOT-LUCKY STOPPED");
  for (int i = 0; i < 12; i++) { notify("NOT LUCKY - STOPPED"); sleep(5); }
}

int main(void) {
  g_logfd = open("/data/kex_hvscan4.txt", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
  mkdir("/mnt/usb0/hvwatch", 0777);

  uint64_t start = MIN_START;
  uint64_t end   = 0x5ff00000ull;

  snprintf(b, sizeof b, "hvwatch-fast scan 0x%llx..0x%llx dmap=0x%lx (2MB chunks)",
           (unsigned long long)start, (unsigned long long)end,
           (unsigned long)KERNEL_ADDRESS_DMAP_BASE);
  logline(b);
  notify("hvwatch: scan started (fast, 0x%llx..0x%llx)", (unsigned long long)start, (unsigned long long)end);

  /* optional suspend->resume mode: if /data/hvwatch_suspend.txt exists, trigger
   * rest mode; if this process survives the resume, scan immediately after. */
  int sf = open("/data/hvwatch_suspend.txt", O_RDONLY);
  if (sf >= 0) {
    close(sf);
    void *event = NULL;
    if (sceKernelOpenEventFlag(&event, "SceSystemStateMgrStatus") == 0) {
      sceKernelNotifySystemSuspendStart();
      sceKernelSetEventFlag(event, 0x400);
      sceKernelCloseEventFlag(&event);
      notify("hvwatch: suspended - press power to resume");
      logline("suspended (suspend-mode), waiting for resume");
      sleep(20);   /* freeze across suspend, continue on resume */
      notify("hvwatch: resumed - scanning");
      logline("resumed, scanning");
    }
  }

  unsigned long dumps = 0;
  uint64_t last256 = 0;

  for (uint64_t off = start; off < end; off += BIGCHUNK) {
    if (dumps == 0 && off >= NOT_LUCKY_THRESHOLD) { notlucky_stop(); return 0; }

    int32_t r = kernel_copyout(KERNEL_ADDRESS_DMAP_BASE + (intptr_t)off, big, BIGCHUNK);
    if (r != 0) {
      /* chunk has a not-present page -> 4KB fallback */
      for (uint64_t po = 0; po < BIGCHUNK && off + po < end; po += PAGE) {
        uint64_t a = off + po;
        int32_t pr = kernel_copyout(KERNEL_ADDRESS_DMAP_BASE + (intptr_t)a, page, PAGE);
        if (pr != 0) continue;
        memset(tmask, 0, sizeof tmask);
        detect_tables(page, PAGE, tmask);
        uint32_t coff = 0;
        if (scan_page(page, PAGE, tmask, &coff) && looks_like_code(page, PAGE)) {
          char name[96];
          snprintf(name, sizeof name, "/mnt/usb0/hvwatch/cluster_%llx.bin", (unsigned long long)a);
          int d = open(name, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
          if (d >= 0) { write(d, page, PAGE); fsync(d); close(d); }
          snprintf(b, sizeof b, "CLUSTER page=0x%llx +0x%x -> %s", (unsigned long long)a, coff, name);
          logline(b);
          dumps++;
          if (dumps == 1) {
            notify("hvwatch: LUCKY at 0x%llx", (unsigned long long)a);
            int rf = open("/mnt/usb0/hvwatch/RESULT.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (rf >= 0) { snprintf(b, sizeof b, "dumps=%lu\nLUCKY\n", dumps); write(rf, b, strlen(b)); fsync(rf); close(rf); }
            return 0;
          }
        }
      }
    } else {
      for (uint64_t po = 0; po < BIGCHUNK; po += PAGE) {
        uint64_t a = off + po;
        memset(tmask, 0, sizeof tmask);
        detect_tables(big + po, PAGE, tmask);
        uint32_t coff = 0;
        if (scan_page(big + po, PAGE, tmask, &coff) && looks_like_code(big + po, PAGE)) {
          char name[96];
          snprintf(name, sizeof name, "/mnt/usb0/hvwatch/cluster_%llx.bin", (unsigned long long)a);
          int d = open(name, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
          if (d >= 0) { write(d, big + po, PAGE); fsync(d); close(d); }
          snprintf(b, sizeof b, "CLUSTER page=0x%llx +0x%x -> %s", (unsigned long long)a, coff, name);
          logline(b);
          dumps++;
          if (dumps == 1) {
            notify("hvwatch: LUCKY at 0x%llx", (unsigned long long)a);
            int rf = open("/mnt/usb0/hvwatch/RESULT.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (rf >= 0) { snprintf(b, sizeof b, "dumps=%lu\nLUCKY\n", dumps); write(rf, b, strlen(b)); fsync(rf); close(rf); }
            return 0;
          }
        }
      }
    }

    if ((off >> 28) != last256) {
      last256 = off >> 28;
      int pct = (int)((off - start) * 100ull / (end - start));
      snprintf(b, sizeof b, "scanned 0x%llx MB (%d%%)", (unsigned long long)(off >> 20), pct);
      logline(b);
      notify("hvwatch: %d%% done (%s)", pct, dumps ? "LUCKY" : "NOT LUCKY");
    }
  }

  notlucky_stop();
  return 0;
}
