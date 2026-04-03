/*
 * macos_apt_detector.c  — v3.0
 *
 * APT UI Interference Detector for macOS
 * Mirrors Windows APT detector logic using native macOS APIs.
 *
 * CHANGELOG
 * ─────────
 * v3.0 (fixes remaining false-positives from v2 run):
 *   FP-7  LaunchPersist recency check hit Adobe plists installed 11 days ago.
 *         Fix: reduced window from 14 → 7 days; added known-vendor whitelist
 *         so major commercial software (Adobe, Microsoft, Google, etc.) is
 *         scored at INFO level rather than HIGH.  Score reduced from HIGH→INFO.
 *         The matching plist line is now printed so the user can verify.
 *   FP-8  Adobe agsservice.plist matched script-path regex because Adobe
 *         Genuine Service legitimately ships a .sh helper.  Known-vendor
 *         plists now score as INFO (not CRITICAL) for this pattern.
 *   FP-9  Little Snitch and ProtectStar AntivirusAI were scored at HIGH
 *         (same as unknown extensions) even though the user intentionally
 *         installed them.  Known-legitimate security tool bundle IDs now score
 *         as INFO with an explicit "verify this is your installation" note.
 *         Unknown extensions retain SCORE_HIGH.
 *   FP-10 Score thresholds recalibrated.  Legitimate known-software installs
 *         produce INFO-only findings which don't count toward the risk score.
 *         Summary thresholds: LOW < 15, MED < 40, HIGH ≥ 40.
 *   MISC  Build script (build.sh) updated to auto-derive TARGET from SRC
 *         filename (fixes truncated binary name in completion box).
 *
 * v2.0 fixes: FP-1 dylib self-detection, FP-2 System plist grep,
 *             FP-3 overlay whitelist, FP-4 kextstat headers,
 *             FP-5 kIOMasterPortDefault deprecation, FP-6 unused vars.
 *
 * BUILD (free Xcode Command Line Tools only — no paid dev account):
 *   xcode-select --install          # one-time, free
 *   bash build.sh                   # auto-compiles with all flags
 *   — or manually —
 *   clang macos_apt_detector_v3.c -o macos_apt_detector \
 *       -framework CoreFoundation   \
 *       -framework ApplicationServices \
 *       -framework IOKit            \
 *       -framework Security         \
 *       -lproc
 *
 * RUN:
 *   sudo ./macos_apt_detector       # full visibility (recommended)
 *   ./macos_apt_detector            # user-space only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <pwd.h>
#include <libproc.h>
#include <mach-o/dyld.h>

#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>
#include <IOKit/IOKitLib.h>
#include <Security/Security.h>

/* ─── Tuneable thresholds ─────────────────────────────────────── */
#define MAX_PIDS              2048
#define PATH_BUF              4096
#define SCORE_INFO               0   /* known-legit, enumerate only   */
#define SCORE_SUSPICIOUS         5   /* worth a manual look           */
#define SCORE_HIGH              10   /* likely malicious or misconfig  */
#define SCORE_CRITICAL          20   /* strong compromise indicator    */

/* Recency window for LaunchAgent/Daemon modification check (days) */
#define LAUNCH_RECENCY_DAYS      7

/* ─── ANSI colour helpers ─────────────────────────────────────── */
#define RED     "\033[1;31m"
#define YELLOW  "\033[1;33m"
#define GREEN   "\033[1;32m"
#define CYAN    "\033[1;36m"
#define BLUE    "\033[1;34m"
#define RESET   "\033[0m"

/* ─── Global counters ────────────────────────────────────────── */
static int g_total_score   = 0;
static int g_finding_count = 0;
static int g_info_count    = 0;

/*
 * finding() — scored finding (contributes to risk score)
 * info()    — informational note (logged but score = 0)
 */
static void finding(int score, const char *category, const char *detail) {
    g_total_score   += score;
    g_finding_count++;
    const char *colour = (score >= SCORE_CRITICAL) ? RED :
                         (score >= SCORE_HIGH)     ? YELLOW : CYAN;
    printf("  %s[FIND %02d | +%2d pts]%s (%s) %s\n",
           colour, g_finding_count, score, RESET, category, detail);
}

static void info_note(const char *category, const char *detail) {
    g_info_count++;
    printf("  %s[INFO %02d        ]%s (%s) %s\n",
           BLUE, g_info_count, RESET, category, detail);
}

/* ─── Shared helpers ─────────────────────────────────────────── */
static const char *get_home(void) {
    const char *h = getenv("HOME");
    if (h && h[0]) return h;
    struct passwd *pw = getpwuid(getuid());
    return (pw && pw->pw_dir) ? pw->pw_dir : "/var/root";
}

/* Case-insensitive prefix match */
static int ihas_prefix(const char *s, const char *prefix) {
    size_t plen = strlen(prefix);
    if (strlen(s) < plen) return 0;
    char lbuf[PATH_BUF]; char lpfx[PATH_BUF];
    for (size_t i = 0; i < plen && i < PATH_BUF-1; i++)
        lpfx[i] = tolower((unsigned char)prefix[i]);
    lpfx[plen] = 0;
    for (size_t i = 0; i < plen && i < PATH_BUF-1; i++)
        lbuf[i] = tolower((unsigned char)s[i]);
    lbuf[plen] = 0;
    return (strncmp(lbuf, lpfx, plen) == 0);
}

/* ══════════════════════════════════════════════════════════════
 * KNOWN-VENDOR WHITELISTS
 * These don't suppress detection — they change severity from
 * HIGH/CRITICAL → INFO so they don't pollute the risk score.
 * ══════════════════════════════════════════════════════════════ */

/*
 * Known-legitimate LaunchAgent/Daemon bundle ID prefixes.
 * Plists matching these still appear as INFO entries for
 * transparency, but don't contribute to the risk score.
 * FIX-7, FIX-8.
 */
static const char *LEGIT_LAUNCH_PREFIXES[] = {
    "com.adobe.",
    "com.microsoft.",
    "com.google.",
    "com.dropbox.",
    "com.spotify.",
    "com.docker.",
    "com.oracle.",
    "com.vmware.",
    "com.parallels.",
    "com.zoom.",
    "com.webex.",
    "com.slack.",
    "com.github.",
    "com.jetbrains.",
    "com.panic.",          /* Transmit, Nova */
    "com.bjango.",         /* iStatMenus */
    "at.obdev.",           /* Little Snitch */
    "com.nortonsecurity.",
    "com.bitdefender.",
    "com.malwarebytes.",
    "com.protectstar.",    /* AntivirusAI */
    "com.crowdstrike.",
    "com.sentinelone.",
    "com.carbonblack.",
    "com.jamf.",
    "com.kandji.",
    "com.mosyle.",
    "com.steam.",
    "com.valvesoftware.",
    "com.steinberg.",
    "com.ableton.",
    "com.focusrite.",
    "com.xlnaudio.",
    NULL
};

static int is_legit_launch_prefix(const char *plist_name) {
    for (int i = 0; LEGIT_LAUNCH_PREFIXES[i]; i++)
        if (ihas_prefix(plist_name, LEGIT_LAUNCH_PREFIXES[i]))
            return 1;
    return 0;
}

/*
 * Known-legitimate security tool system extension bundle IDs.
 * These are scored as INFO (not HIGH) because:
 *   (a) They are well-known, signed products.
 *   (b) The user would know if they installed them.
 * The note prompts the user to verify the installation is theirs.
 * FIX-9.
 */
static const char *LEGIT_SECURITY_EXTENSIONS[] = {
    "at.obdev.littlesnitch",
    "com.protectstar.antivirus",
    "com.malwarebytes.",
    "com.nortonsecurity.",
    "com.bitdefender.",
    "com.crowdstrike.",
    "com.sentinelone.",
    "com.carbonblack.",
    "com.eset.",
    "com.kaspersky.",
    "com.sophos.",
    "com.trendmicro.",
    "com.webroot.",
    NULL
};

static int is_legit_security_extension(const char *bundle_id) {
    for (int i = 0; LEGIT_SECURITY_EXTENSIONS[i]; i++)
        if (ihas_prefix(bundle_id, LEGIT_SECURITY_EXTENSIONS[i]))
            return 1;
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * TCC.db helper
 * ══════════════════════════════════════════════════════════════ */
#define TCC_DB_SUFFIX "/Library/Application Support/com.apple.TCC/TCC.db"
#define TCC_SYS_DB    "/Library/Application Support/com.apple.TCC/TCC.db"

static void audit_tcc_db(const char *db_path,
                          const char *service,
                          const char *label) {
    char cmd[PATH_BUF * 2];
    snprintf(cmd, sizeof(cmd),
             "sqlite3 -separator '|' \"%s\" "
             "\"SELECT client,auth_value FROM access "
             " WHERE service='%s' AND auth_value=2;\" 2>/dev/null",
             db_path, service);

    FILE *fp = popen(cmd, "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) < 3) continue;
        char buf[600];
        snprintf(buf, sizeof(buf), "%s  → %s", label, line);
        finding(SCORE_HIGH, "TCC/Permission", buf);
    }
    pclose(fp);
}

/* ══════════════════════════════════════════════════════════════
 * 1. CGEventTap detection
 * ══════════════════════════════════════════════════════════════ */
static void check_event_taps(void) {
    printf("\n" CYAN "── [1] CGEventTap / Keylogger Hooks ──" RESET "\n");

    io_iterator_t iter = 0;
    kern_return_t kr = IOServiceGetMatchingServices(
        kIOMainPortDefault,
        IOServiceMatching("IOHIDEventSystemUserClient"),
        &iter);

    if (kr == KERN_SUCCESS) {
        io_service_t svc;
        int tap_count = 0;
        while ((svc = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
            tap_count++;
            IOObjectRelease(svc);
        }
        IOObjectRelease(iter);
        if (tap_count > 0) {
            char buf[160];
            snprintf(buf, sizeof(buf),
                     "%d IOHIDEventSystemUserClient connection(s) open "
                     "(active HID event listeners)", tap_count);
            finding(SCORE_SUSPICIOUS, "EventTap", buf);
        } else {
            printf("  " GREEN "[OK]" RESET
                   " No IOHIDEventSystemUserClient connections detected.\n");
        }
    }

    int pids[MAX_PIDS];
    int npids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids)) / sizeof(int);

    for (int i = 0; i < npids; i++) {
        if (pids[i] == 0) continue;
        char path[PATH_BUF] = {0};
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) continue;

        if (strstr(path, "osascript") || strstr(path, "Script Editor")) {
            struct proc_taskinfo ti;
            if (proc_pidinfo(pids[i], PROC_PIDTASKINFO, 0,
                             &ti, sizeof(ti)) > 0) {
                char buf[PATH_BUF];
                snprintf(buf, sizeof(buf), "PID %-6d  path: %s", pids[i], path);
                finding(SCORE_HIGH, "osascript/JXA", buf);
            }
        }
    }
}

/* ══════════════════════════════════════════════════════════════
 * 2. Accessibility (AX) API abuse
 * ══════════════════════════════════════════════════════════════ */
static void check_accessibility(void) {
    printf("\n" CYAN "── [2] Accessibility (AX API) Abuse ──" RESET "\n");

    if (AXIsProcessTrustedWithOptions(NULL))
        printf("  " GREEN "[OK]" RESET " AXIsProcessTrusted: this process is trusted.\n");

    char user_tcc[PATH_BUF];
    snprintf(user_tcc, sizeof(user_tcc), "%s%s", get_home(), TCC_DB_SUFFIX);

    audit_tcc_db(user_tcc,  "kTCCServiceAccessibility", "Accessibility (user)");
    audit_tcc_db(TCC_SYS_DB,"kTCCServiceAccessibility", "Accessibility (system)");
}

/* ══════════════════════════════════════════════════════════════
 * 3. Screen capture abuse
 * ══════════════════════════════════════════════════════════════ */
static void check_screen_capture(void) {
    printf("\n" CYAN "── [3] Screen Capture Permission Holders ──" RESET "\n");

    char user_tcc[PATH_BUF];
    snprintf(user_tcc, sizeof(user_tcc), "%s%s", get_home(), TCC_DB_SUFFIX);

    audit_tcc_db(user_tcc,  "kTCCServiceScreenCapture", "ScreenCapture (user)");
    audit_tcc_db(TCC_SYS_DB,"kTCCServiceScreenCapture", "ScreenCapture (system)");

    static const char *apt_capture_names[] = {
        "screcorder", "vnc",  "rfb",
        "teamviewer", "anydesk",  "gotomypc",
        "logmein",    "radmin",   "dameware",
        "screenconnect", "cobalt", "metasploit",
        NULL
    };

    int pids[MAX_PIDS];
    int npids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids)) / sizeof(int);
    int hits = 0;

    for (int i = 0; i < npids; i++) {
        if (pids[i] == 0) continue;
        char path[PATH_BUF] = {0};
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) continue;

        char lpath[PATH_BUF];
        for (size_t c = 0; c < strlen(path); c++)
            lpath[c] = tolower((unsigned char)path[c]);
        lpath[strlen(path)] = 0;

        for (int n = 0; apt_capture_names[n]; n++) {
            if (strstr(lpath, apt_capture_names[n])) {
                char buf[PATH_BUF];
                snprintf(buf, sizeof(buf),
                         "PID %-6d  match='%s'  path: %s",
                         pids[i], apt_capture_names[n], path);
                finding(SCORE_HIGH, "ScreenCapture", buf);
                hits++;
            }
        }
    }
    if (!hits)
        printf("  " GREEN "[OK]" RESET
               " No suspicious screen-capture processes detected.\n");
}

/* ══════════════════════════════════════════════════════════════
 * 4. Input monitoring
 * ══════════════════════════════════════════════════════════════ */
static void check_input_monitoring(void) {
    printf("\n" CYAN "── [4] Input Monitoring Permission Holders ──" RESET "\n");

    char user_tcc[PATH_BUF];
    snprintf(user_tcc, sizeof(user_tcc), "%s%s", get_home(), TCC_DB_SUFFIX);

    audit_tcc_db(user_tcc,  "kTCCServiceListenEvent", "InputMonitor (user)");
    audit_tcc_db(TCC_SYS_DB,"kTCCServiceListenEvent", "InputMonitor (system)");
    audit_tcc_db(user_tcc,  "kTCCServicePostEvent",   "PostEvent (user)");
}

/* ══════════════════════════════════════════════════════════════
 * 5. dylib injection
 * ══════════════════════════════════════════════════════════════ */
static const char *LEGIT_DYLIB_PREFIXES[] = {
    "/usr/lib/",
    "/System/Library/",
    "/Library/Apple/",
    "/usr/local/lib/",
    "/opt/homebrew/lib/",
    "/Library/Frameworks/",
    NULL
};

static int is_legit_dylib(const char *path) {
    for (int i = 0; LEGIT_DYLIB_PREFIXES[i]; i++)
        if (strncmp(path, LEGIT_DYLIB_PREFIXES[i],
                    strlen(LEGIT_DYLIB_PREFIXES[i])) == 0)
            return 1;
    return 0;
}

static int has_dylib_suffix(const char *path) {
    size_t len = strlen(path);
    return (len > 6 && strcmp(path + len - 6, ".dylib") == 0);
}

static void check_dylib_injection(void) {
    printf("\n" CYAN "── [5] dylib Injection / DYLD Manipulation ──" RESET "\n");

    const char *dyld_insert = getenv("DYLD_INSERT_LIBRARIES");
    if (dyld_insert) {
        char buf[PATH_BUF];
        snprintf(buf, sizeof(buf), "DYLD_INSERT_LIBRARIES=%s", dyld_insert);
        finding(SCORE_CRITICAL, "dylib/DYLD", buf);
    } else {
        printf("  " GREEN "[OK]" RESET
               " DYLD_INSERT_LIBRARIES not set in environment.\n");
    }

    uint32_t count = _dyld_image_count();
    int inj_found = 0;
    for (uint32_t i = 1; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (!has_dylib_suffix(name)) continue;
        if (!is_legit_dylib(name)) {
            char buf[PATH_BUF];
            snprintf(buf, sizeof(buf),
                     "Non-standard dylib in current process: %s", name);
            finding(SCORE_SUSPICIOUS, "dylib/inject", buf);
            inj_found++;
        }
    }
    if (!inj_found)
        printf("  " GREEN "[OK]" RESET
               " No non-standard dylibs in current process.\n");

    int pids[MAX_PIDS];
    int npids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids)) / sizeof(int);

    for (int i = 0; i < npids; i++) {
        if (pids[i] == 0 || pids[i] == getpid()) continue;

        int mib[3] = { CTL_KERN, KERN_PROCARGS2, pids[i] };
        size_t size = 0;
        if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size == 0) continue;

        char *args = malloc(size);
        if (!args) continue;
        if (sysctl(mib, 3, args, &size, NULL, 0) != 0) { free(args); continue; }

        char *p = args + sizeof(int);
        char *end = args + size;
        while (p < end && *p) p++;
        while (p < end && !*p) p++;

        while (p < end) {
            if (*p == 0) { p++; continue; }
            if (strncmp(p, "DYLD_INSERT_LIBRARIES=", 22) == 0 ||
                strncmp(p, "DYLD_LIBRARY_PATH=",    18) == 0 ||
                strncmp(p, "DYLD_FRAMEWORK_PATH=",  20) == 0) {
                char procpath[PATH_BUF] = {0};
                proc_pidpath(pids[i], procpath, sizeof(procpath));
                char buf[PATH_BUF * 2];
                snprintf(buf, sizeof(buf),
                         "PID %-6d (%s)  env: %.200s",
                         pids[i], procpath, p);
                finding(SCORE_CRITICAL, "dylib/DYLD_env", buf);
            }
            while (p < end && *p) p++;
        }
        free(args);
    }
}

/* ══════════════════════════════════════════════════════════════
 * 6. Launch persistence anomalies
 *
 * v3 changes (FP-7, FP-8):
 *   - Recency window reduced: 14 → LAUNCH_RECENCY_DAYS (7) days.
 *   - Known-vendor plists: recency hit → INFO (score 0), not HIGH.
 *   - Script-path match for known vendors → INFO, not CRITICAL.
 *   - The matched plist line is now printed for manual verification.
 * ══════════════════════════════════════════════════════════════ */
static void check_launch_persistence(void) {
    printf("\n" CYAN "── [6] LaunchAgent / LaunchDaemon Persistence ──" RESET "\n");

    char user_agents[PATH_BUF];
    snprintf(user_agents, sizeof(user_agents),
             "%s/Library/LaunchAgents", get_home());

    const char *paths[] = {
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        user_agents,
        NULL
    };

    time_t now = time(NULL);
    int found_any = 0;

    for (int pi = 0; paths[pi]; pi++) {
        int is_system = (strncmp(paths[pi], "/System/", 8) == 0);

        DIR *d = opendir(paths[pi]);
        if (!d) continue;

        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            if (!strstr(de->d_name, ".plist")) continue;

            char full[PATH_BUF];
            snprintf(full, sizeof(full), "%s/%s", paths[pi], de->d_name);

            struct stat st;
            if (stat(full, &st) != 0) continue;

            double age_days = difftime(now, st.st_mtime) / 86400.0;

            /* Determine if this plist belongs to a known-legitimate vendor */
            int is_legit = is_legit_launch_prefix(de->d_name);

            /* ── Recency check ── */
            if (!is_system && age_days < (double)LAUNCH_RECENCY_DAYS) {
                char buf[PATH_BUF];
                snprintf(buf, sizeof(buf),
                         "Modified %.1f days ago: %s", age_days, full);
                if (is_legit) {
                    /* Known vendor — informational only */
                    info_note("LaunchPersist", buf);
                } else {
                    finding(SCORE_HIGH, "LaunchPersist", buf);
                    found_any = 1;
                }
            }

            /* ── Script / temp-path content check ──
             * Skipped for /System/ (Apple's own daemons).
             * Known vendors: INFO severity.
             * Unknown vendors: CRITICAL severity.
             * The matching line is printed for manual inspection.
             */
            if (is_system) continue;

            char cmd[PATH_BUF * 2];
            snprintf(cmd, sizeof(cmd),
                "grep -iE "
                "'<string>[^<]*/tmp/[^<]*</string>"
                "|<string>[^<]*/var/tmp/[^<]*</string>"
                "|<string>[^<]+\\.(sh|py|rb|pl|command)</string>' "
                "\"%s\" 2>/dev/null | head -3",
                full);

            FILE *fp = popen(cmd, "r");
            if (fp) {
                char matched_line[512] = {0};
                fgets(matched_line, sizeof(matched_line), fp);
                pclose(fp);

                if (matched_line[0]) {
                    matched_line[strcspn(matched_line, "\n")] = 0;
                    /* Trim leading whitespace for display */
                    char *trimmed = matched_line;
                    while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

                    char buf2[PATH_BUF];
                    snprintf(buf2, sizeof(buf2),
                             "%s  →  %s", full, trimmed);

                    if (is_legit) {
                        info_note("LaunchPersist/Script", buf2);
                    } else {
                        finding(SCORE_CRITICAL, "LaunchPersist/Script", buf2);
                        found_any = 1;
                    }
                }
            }
        }
        closedir(d);
    }

    if (!found_any)
        printf("  " GREEN "[OK]" RESET
               " No suspicious LaunchAgent/Daemon entries found.\n");
}

/* ══════════════════════════════════════════════════════════════
 * 7. Overlay / transparent window detection
 * ══════════════════════════════════════════════════════════════ */
static const char *SAFE_OVERLAY_OWNERS[] = {
    "Window Server", "Control Center", "Dock", "SystemUIServer",
    "NotificationCenter", "Spotlight", "loginwindow", "AirPlayUIAgent",
    "Siri", "com.apple.dock.extra", "Accessibility Inspector",
    "ScreenSaverEngine", "universalaccessd", NULL
};

static int is_safe_overlay_owner(const char *name) {
    for (int i = 0; SAFE_OVERLAY_OWNERS[i]; i++)
        if (strcmp(name, SAFE_OVERLAY_OWNERS[i]) == 0) return 1;
    return 0;
}

static void check_overlay_windows(void) {
    printf("\n" CYAN "── [7] Suspicious Overlay Windows ──" RESET "\n");

    CFArrayRef windows = CGWindowListCopyWindowInfo(
        kCGWindowListOptionAll | kCGWindowListExcludeDesktopElements,
        kCGNullWindowID);

    if (!windows) {
        printf("  " YELLOW "[WARN]" RESET
               " CGWindowListCopyWindowInfo unavailable"
               " (run as root or grant Screen Recording permission).\n");
        return;
    }

    CFIndex count = CFArrayGetCount(windows);
    int suspicious = 0;

    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef w = CFArrayGetValueAtIndex(windows, i);

        CFNumberRef layerRef = CFDictionaryGetValue(w, kCGWindowLayer);
        int layer = 0;
        if (layerRef) CFNumberGetValue(layerRef, kCFNumberIntType, &layer);

        CFNumberRef alphaRef = CFDictionaryGetValue(w, kCGWindowAlpha);
        double alpha = 1.0;
        if (alphaRef) CFNumberGetValue(alphaRef, kCFNumberDoubleType, &alpha);

        CFNumberRef pidRef = CFDictionaryGetValue(w, kCGWindowOwnerPID);
        int owner_pid = 0;
        if (pidRef) CFNumberGetValue(pidRef, kCFNumberIntType, &owner_pid);

        CFStringRef ownerRef = CFDictionaryGetValue(w, kCGWindowOwnerName);
        char owner[256] = "unknown";
        if (ownerRef)
            CFStringGetCString(ownerRef, owner, sizeof(owner),
                               kCFStringEncodingUTF8);

        if (is_safe_overlay_owner(owner)) continue;

        int high_layer = (layer >= 1000);
        int invisible  = (alpha < 0.05 && alpha >= 0.0);

        if (high_layer && invisible) {
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "PID %-6d  owner='%s'  layer=%d  alpha=%.3f  "
                     "[INVISIBLE OVERLAY]",
                     owner_pid, owner, layer, alpha);
            finding(SCORE_CRITICAL, "OverlayWindow", buf);
            suspicious++;
        } else if (layer >= 2000) {
            char buf[512];
            snprintf(buf, sizeof(buf),
                     "PID %-6d  owner='%s'  layer=%d  alpha=%.2f",
                     owner_pid, owner, layer, alpha);
            finding(SCORE_SUSPICIOUS, "OverlayWindow", buf);
            suspicious++;
        }
    }

    CFRelease(windows);

    if (!suspicious)
        printf("  " GREEN "[OK]" RESET
               " No suspicious overlay windows detected.\n");
}

/* ══════════════════════════════════════════════════════════════
 * 8. Kernel Extensions / System Extensions
 *
 * v3 change (FP-9):
 *   Known-legitimate security tools (Little Snitch, ProtectStar, etc.)
 *   are scored as INFO (score=0) instead of HIGH (score=10).
 *   They still appear in output with a "verify your installation" note.
 *   Unknown third-party extensions retain SCORE_HIGH.
 * ══════════════════════════════════════════════════════════════ */
static void check_kexts(void) {
    printf("\n" CYAN "── [8] Kernel Extensions / System Extensions ──" RESET "\n");

    struct { const char *cmd; const char *label; } checks[] = {
        {
            "kextstat 2>/dev/null"
            " | grep -v '^Index'"
            " | grep -iv 'com.apple'"
            " | grep -v '^[[:space:]]*$'",
            "kext"
        },
        {
            "systemextensionsctl list 2>/dev/null"
            " | grep -E '^[[:space:]]*\\*'"
            " | grep -iv 'com.apple'",
            "sysext"
        },
        { NULL, NULL }
    };

    for (int i = 0; checks[i].cmd; i++) {
        FILE *fp = popen(checks[i].cmd, "r");
        if (!fp) continue;
        char line[512];
        int found = 0;
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) < 4) continue;

            char display[600];
            snprintf(display, sizeof(display),
                     "[%s] %s", checks[i].label, line);

            /*
             * FIX-9: Check if the bundle ID belongs to a known-legitimate
             * security product.  We scan the line for matching prefixes.
             */
            int is_legit_sec = 0;
            {
                char lline[512];
                for (size_t c = 0; c < strlen(line) && c < 511; c++)
                    lline[c] = tolower((unsigned char)line[c]);
                lline[strlen(line) < 511 ? strlen(line) : 511] = 0;

                for (int n = 0; LEGIT_SECURITY_EXTENSIONS[n]; n++) {
                    if (strstr(lline, LEGIT_SECURITY_EXTENSIONS[n])) {
                        is_legit_sec = 1;
                        break;
                    }
                }
            }

            if (is_legit_sec) {
                char info_buf[700];
                snprintf(info_buf, sizeof(info_buf),
                         "%s  [known security tool — verify this is your install]",
                         display);
                info_note("Kext/SysExt", info_buf);
            } else {
                finding(SCORE_HIGH, "Kext/SysExt", display);
            }
            found = 1;
        }
        pclose(fp);
        if (!found)
            printf("  " GREEN "[OK]" RESET
                   " No third-party %s entries found.\n", checks[i].label);
    }
}

/* ══════════════════════════════════════════════════════════════
 * 9. Codesign anomalies
 * ══════════════════════════════════════════════════════════════ */
static void check_codesign(void) {
    printf("\n" CYAN "── [9] Codesign Anomalies (UI-facing processes) ──" RESET "\n");

    int pids[MAX_PIDS];
    int npids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids)) / sizeof(int);
    int reported = 0;

    for (int i = 0; i < npids; i++) {
        if (pids[i] == 0) continue;
        char path[PATH_BUF] = {0};
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) continue;

        if (strncmp(path, "/System/",         8) == 0) continue;
        if (strncmp(path, "/usr/",            5) == 0) continue;
        if (strncmp(path, "/Library/Apple/", 15) == 0) continue;
        if ((i % 4) != 0) continue;

        char cmd[PATH_BUF * 2];
        snprintf(cmd, sizeof(cmd),
                 "codesign -v --strict \"%s\" 2>&1", path);
        FILE *fp = popen(cmd, "r");
        if (!fp) continue;

        char out[256] = {0};
        fgets(out, sizeof(out), fp);
        pclose(fp);

        if (strstr(out, "not signed") ||
            strstr(out, "adhoc")      ||
            strstr(out, "invalid")    ||
            strstr(out, "CSSMERR")) {
            out[strcspn(out, "\n")] = 0;
            char buf[PATH_BUF * 2];
            snprintf(buf, sizeof(buf),
                     "PID %-6d  codesign: '%s'  path: %s",
                     pids[i], out[0] ? out : "unknown", path);
            finding(SCORE_HIGH, "Codesign", buf);
            reported++;
        }
    }
    if (!reported)
        printf("  " GREEN "[OK]" RESET
               " Sampled UI-facing processes appear properly signed.\n");
}

/* ══════════════════════════════════════════════════════════════
 * 10. Known APT IOC process names
 * ══════════════════════════════════════════════════════════════ */
static const char *APT_IOC_NAMES[] = {
    "fruitfly",      "calisto",       "coldroot",      "windtail",
    "darkhydrus",    "shlayer",       "bundlore",      "pirrit",
    "macma",         "gimmick",       "subzero",       "mactans",
    "thunderstrike", "proton",        "elmedia",       "crossrider",
    "dok",           "keydnap",       "crisis",        "mokes",
    "evilquest",     "osx.dacls",     "osx.cdds",      "osx.xcsset",
    "osx.zuru",      "osx.lador",     "osx.dummy",     "osx.netwire",
    "osx.coinminer", "reptile",       "cobaltstrike",  "pwnkit",
    "lsassreader",   "geacon",        "nuclear",       "nightdoor",
    "rustbucket",    "swiftbelt",     "smoothoperator",
    NULL
};

static void check_apt_ioc_names(void) {
    printf("\n" CYAN "── [10] Known APT IOC Process Names ──" RESET "\n");

    int pids[MAX_PIDS];
    int npids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids)) / sizeof(int);
    int hits = 0;

    for (int i = 0; i < npids; i++) {
        if (pids[i] == 0) continue;
        char path[PATH_BUF] = {0};
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) continue;

        char lpath[PATH_BUF];
        size_t plen = strlen(path);
        for (size_t c = 0; c < plen; c++)
            lpath[c] = tolower((unsigned char)path[c]);
        lpath[plen] = 0;

        for (int n = 0; APT_IOC_NAMES[n]; n++) {
            if (strstr(lpath, APT_IOC_NAMES[n])) {
                char buf[PATH_BUF];
                snprintf(buf, sizeof(buf),
                         "PID %-6d  IOC='%s'  path: %s",
                         pids[i], APT_IOC_NAMES[n], path);
                finding(SCORE_CRITICAL, "APT-IOC", buf);
                hits++;
            }
        }
    }
    if (!hits)
        printf("  " GREEN "[OK]" RESET
               " No known APT IOC process names found.\n");
}

/* ══════════════════════════════════════════════════════════════
 * Summary
 *
 * v3 change (FP-10): INFO entries (score=0) are counted and displayed
 * separately.  They do not affect the risk score or threshold.
 * Thresholds: LOW < 15, MED < 40, HIGH ≥ 40.
 * ══════════════════════════════════════════════════════════════ */
static void print_summary(void) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  APT UI INTERFERENCE SCAN — SUMMARY                   \n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Scored Findings : %d\n", g_finding_count);
    printf("  Info Notes      : %d  (known-legit software, score=0)\n",
           g_info_count);
    printf("  Risk Score      : %d  ", g_total_score);

    if (g_total_score == 0) {
        printf(GREEN  "[ CLEAN ]" RESET "\n");
    } else if (g_total_score < 15) {
        printf(CYAN   "[ LOW   ]" RESET " – Review findings manually.\n");
    } else if (g_total_score < 40) {
        printf(YELLOW "[ MED   ]" RESET " – Investigate suspicious items.\n");
    } else {
        printf(RED    "[ HIGH  ]" RESET
               " – Active compromise indicators present!\n");
    }

    if (g_info_count > 0) {
        printf("\n  " BLUE "[INFO]" RESET
               " entries above are known-legitimate software.\n"
               "  Verify each is an install you recognise.\n");
    }

    printf("\n  Recommended follow-up steps:\n");
    printf("    1. Review each FIND item above with manual inspection.\n");
    printf("    2. Cross-reference TCC.db entries vs expected app bundles.\n");
    printf("    3. For LaunchAgent hits: inspect full plist with:\n");
    printf("         cat /Library/LaunchDaemons/<name>.plist\n");
    printf("    4. Reboot in safe mode and re-run to confirm persistence.\n");
    printf("    5. Collect IOCs:\n");
    printf("         sudo fs_usage -f filesys\n");
    printf("         sudo opensnoop\n");
    printf("         sudo tcpdump -i en0 -nn\n");
    printf("    6. Watch TCC decisions live:\n");
    printf("         log stream --predicate "
           "'subsystem == \"com.apple.TCC\"'\n");
    printf("═══════════════════════════════════════════════════════\n\n");
}

/* ══════════════════════════════════════════════════════════════
 * main
 * ══════════════════════════════════════════════════════════════ */
int main(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║   macOS APT UI Interference Detector  v3.0            ║\n");
    printf("║   Build: Xcode CLT (clang) — no paid signing key      ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");

    if (geteuid() != 0) {
        printf(YELLOW
               "\n  [NOTE] Not running as root. Some checks (TCC.db reads,\n"
               "         kext list, all-process env scan) require:\n"
               "           sudo ./macos_apt_detector\n"
               RESET "\n");
    }

    check_event_taps();
    check_accessibility();
    check_screen_capture();
    check_input_monitoring();
    check_dylib_injection();
    check_launch_persistence();
    check_overlay_windows();
    check_kexts();
    check_codesign();
    check_apt_ioc_names();

    print_summary();
    return (g_total_score > 0) ? 1 : 0;
}
