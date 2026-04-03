# macOS APT UI Interference Detector (v3.0)

A lightweight, native C-based forensic tool designed to detect Advanced Persistent Threat (APT) indicators, UI redlining, and unauthorized persistence on macOS. 

This tool mirrors common Windows-based APT detection logic but is built specifically for the macOS ecosystem, utilizing native APIs to audit **TCC permissions**, **Event Taps**, **dylib injections**, and **LaunchAgent anomalies**.

## 🛡️ Key Detection Modules

The detector performs a multi-layered scan across 10 critical vectors:

* **HID & Event Taps:** Detects active keyloggers or IOHIDEventSystem hooks.
* **TCC.db Auditing:** Directly queries System and User SQLite databases for suspicious Accessibility, Screen Recording, and Input Monitoring permissions.
* **DYLD Injection:** Scans the environment for `DYLD_INSERT_LIBRARIES` and non-standard dylibs in the process memory space.
* **Persistence Analysis:** Identifies LaunchAgents/Daemons modified within a 7-day window or containing suspicious script-path execution (e.g., `/tmp/`, `.sh`, `.py`).
* **Overlay Detection:** Identifies invisible or high-layer "clickjacking" windows that may be intercepting UI interactions.
* **System Extensions:** Enumerates third-party Kexts and System Extensions with built-in whitelisting for known security vendors (Little Snitch, etc.).
* **Code Signature Verification:** Validates the signatures of active UI-facing processes to find ad-hoc or unsigned binaries.
* **IOC Pattern Matching:** Scans process strings against a library of known macOS-specific malware (FruitFly, Shlayer, EvilQuest, etc.).

## 🚀 Quick Start

### Prerequisites
* **macOS 12.0+**
* **Xcode Command Line Tools** (No paid Developer Account required)
    ```bash
    xcode-select --install
    ```

### Build
The included build script auto-detects your architecture (Intel or Apple Silicon) and compiles with the necessary frameworks (`CoreFoundation`, `IOKit`, `Security`).

```bash
bash build.sh
```

### Run
To audit system-level TCC databases and kernel extensions, the tool should be run with root privileges:

```bash
sudo ./macos_apt_detector_v3
```

## 📊 Risk Scoring Logic (v3.0)

Version 3.0 introduces a refined scoring system to minimize false positives:

| Level | Score | Action |
| :--- | :--- | :--- |
| **[INFO]** | 0 pts | Known-legitimate vendors (Adobe, Google, Microsoft, etc.). Manual verification suggested. |
| **[LOW]** | < 15 pts | Minor anomalies; likely misconfigurations or power-user tools. |
| **[MED]** | 15–39 pts | Suspicious items detected; investigation recommended. |
| **[HIGH]** | 40+ pts | Active compromise indicators or high-risk persistence present. |

## 🛠️ Technical Details

* **Language:** Pure C (C99/C11).
* **Dependencies:** Zero external libraries. Uses native Apple Frameworks and `libproc`.
* **Architecture:** Universal (tested on `arm64`).

## ⚖️ Disclaimer

*This tool is for educational and forensic purposes only. It is intended to assist security professionals in identifying potential threats. Detection of a "suspicious" item does not always indicate a compromise.*

---

**Author:** Michael Lazin  
**License:** MIT  
**Version:** 3.0.0 (2026)
