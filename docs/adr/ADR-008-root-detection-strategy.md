# ADR-008: Root Detection Strategy

**Status:** Accepted

## Context

Root access fundamentally undermines the Android security model by granting apps unrestricted access to the system. Rooted devices enable hooking frameworks (Frida, Xposed), app data extraction, and bypass of all other security checks. Root detection is the most-requested feature in mobile security SDKs.

Modern root solutions (Magisk, KernelSU, APatch) actively hide their presence via mount namespace isolation (Shamiko), kernel-level VFS interception (SUSFS), and custom syscalls (APatch SuperCall #45).

## Decision

Implement a RootDetector with 7 check groups using the same two-tier confidence model as other detectors (hard signals + weighted soft signals).

### Checks Implemented (v0.1.0)

| Check | Tier | Weight | Rationale |
|-------|------|--------|-----------|
| SU binary paths (15 locations) | Soft | 0.7 | Classic root indicator. Magisk DenyList and KernelSU can hide these. |
| Root management apps (8 packages) | Soft | 0.6 | Magisk randomizes its package name. KernelSU uses `me.weishu.kernelsu`. |
| SELinux status | Soft | 0.5 | Production devices enforce SELinux. Rooted devices often set Permissive. |
| Dangerous system properties | Soft | 0.6 | `ro.debuggable=1`, `ro.secure=0`, `service.adb.root=1`. Excludes userdebug/eng builds to avoid false positives on development devices. |
| System partition writability | Hard | - | `/system` mounted `rw` is definitive on production devices. Zero false positives. |
| Test keys | Soft | 0.4 | Low weight because custom ROMs may use test-keys without root. |
| Magisk/KernelSU/APatch artifacts | Soft | 0.8 | `/data/adb/magisk`, `/data/adb/ksu`, `/data/adb/ap`. High weight because these paths are highly specific to root tools. |

### Future Improvements (v0.2.0+)

These techniques require native C implementation with direct syscalls and are planned for a future release:

- `/proc/self/mountinfo` analysis for overlayfs mounts (`dev=KSU`)
- Mount namespace ID comparison (`/proc/1/ns/mnt` vs `/proc/self/ns/mnt`)
- APatch SuperCall #45 probing (syscall with invalid key, check for `-EPERM` vs `-ENOSYS`)
- `/proc/net/unix` scanning for Magisk daemon UDS (32+ char random socket names)
- PID namespace anomaly detection (`getpid()` vs `/proc/self/status` NSpid)

## Consequences

- Root detection is inherently a cat-and-mouse game. Shamiko + SUSFS can hide all file-based artifacts.
- The v0.1.0 implementation catches non-hidden root (Magisk without DenyList, basic SuperSU, KernelSU default config) and provides a solid baseline.
- The modular architecture allows incremental addition of advanced checks without breaking the API.
- File existence checks use Java `File.exists()` — planned migration to `NativeBridge.fileExistsNative()` for Frida resistance.

## References

- OWASP MASTG-TEST-0045: Testing Root Detection
- OWASP MASWE-0097: Root/Jailbreak Detection Not Implemented
- RootBeer: https://github.com/scottyab/rootbeer
- Android-Native-Root-Detector: https://github.com/reveny/Android-Native-Root-Detector
- KernelSU App Profile: https://kernelsu.org/guide/app-profile.html
- APatch SuperCall: https://github.com/bmax121/APatch
