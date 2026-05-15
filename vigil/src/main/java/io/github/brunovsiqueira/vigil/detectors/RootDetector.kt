package io.github.brunovsiqueira.vigil.detectors

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.github.brunovsiqueira.vigil.DetectionCategory
import io.github.brunovsiqueira.vigil.DetectionResult
import io.github.brunovsiqueira.vigil.Evidence
import io.github.brunovsiqueira.vigil.TamperDetector
import io.github.brunovsiqueira.vigil.error.DetectionError
import io.github.brunovsiqueira.vigil.util.SafeExec
import io.github.brunovsiqueira.vigil.util.SystemProps
import java.io.BufferedReader
import java.io.FileReader

/**
 * Detects whether the device has been rooted.
 *
 * Uses 7 check groups split into two tiers:
 * - **Hard signals:** System partition mounted read-write — zero false positives
 *   on production devices.
 * - **Soft signals:** SU binary paths, root management apps, SELinux status,
 *   dangerous system properties, test-keys, Magisk/KernelSU/APatch artifacts.
 *
 * Root detection is inherently a cat-and-mouse game. Magisk's MagiskHide and
 * Shamiko can hide many of these artifacts, but the combination of multiple
 * weak signals still provides meaningful coverage.
 */
class RootDetector : TamperDetector {

    override val name: String = "RootDetector"
    override val category: DetectionCategory = DetectionCategory.ROOT
    override val weight: Float = 1.0f

    override suspend fun detect(context: Context): DetectionResult {
        val errors = mutableListOf<DetectionError>()
        val evidence = mutableListOf<Evidence>()

        checkSuBinaries(evidence, errors)
        checkRootManagementApps(context, evidence, errors)
        checkSeLinuxStatus(evidence, errors)
        checkDangerousSystemProperties(evidence, errors)
        checkSystemPartitionWritability(evidence, errors)
        checkTestKeys(evidence, errors)
        checkMagiskArtifacts(evidence, errors)

        // Advanced checks via native C (direct syscalls)
        if (NativeBridge.isLoaded) {
            checkOverlayFs(evidence, errors)
            checkMagiskUnixSockets(evidence, errors)
            // Note: mount namespace comparison (checkMountNamespace) was REMOVED.
            // On stock Android, Zygote calls unshare(CLONE_NEWNS) for every app
            // (see AOSP Zygote.cpp ensureInAppMountNamespace). This means ALL apps
            // have a different mount namespace than init — the check was always true.
            // Source: platform/frameworks/base/core/jni/com_android_internal_os_Zygote.cpp
            checkApatchSupercall(evidence, errors)
        }

        return buildResult(evidence, errors)
    }

    // ──────────────────────────────────────────────
    // Check 1: SU Binary Detection
    // Weight: 0.7
    //
    // The `su` binary is the primary mechanism for
    // granting root access. Present at well-known
    // paths on rooted devices.
    // ──────────────────────────────────────────────

    private fun checkSuBinaries(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_SU_BINARY, name, errors) {
            val foundPaths = mutableListOf<String>()

            for (path in SU_BINARY_PATHS) {
                if (NativeBridge.fileExists(path)) {
                    foundPaths.add(path)
                }
            }

            val suspicious = foundPaths.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_SU_BINARY,
                    description = if (suspicious) {
                        "SU binary found at ${foundPaths.size} location(s): ${foundPaths.joinToString(", ")}"
                    } else {
                        "No SU binary found in known paths"
                    },
                    rawValue = if (suspicious) foundPaths.joinToString(", ") else "(clean)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 2: Root Management Apps
    // Weight: 0.6
    //
    // Root management apps (Magisk, SuperSU, etc.)
    // are installed to manage root access grants.
    // Their presence is a strong indicator of root.
    // ──────────────────────────────────────────────

    private fun checkRootManagementApps(
        context: Context,
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_ROOT_APPS, name, errors) {
            val foundPackages = mutableListOf<String>()
            val pm = context.packageManager

            for (packageName in ROOT_MANAGEMENT_PACKAGES) {
                try {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(packageName, 0)
                    foundPackages.add(packageName)
                } catch (_: PackageManager.NameNotFoundException) {
                    // Expected — package not installed
                }
            }

            val suspicious = foundPackages.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_ROOT_APPS,
                    description = if (suspicious) {
                        "Root management app(s) installed: ${foundPackages.joinToString(", ")}"
                    } else {
                        "No root management apps detected"
                    },
                    rawValue = if (suspicious) foundPackages.joinToString(", ") else "(clean)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // ──────────────────────────────────────────────
    // Check 3: SELinux Status
    // Weight: 0.5
    //
    // Production builds are compile-time locked to
    // enforcing via ALLOW_PERMISSIVE_SELINUX=false.
    // Source: AOSP platform/system/core/init/selinux.cpp
    //   IsEnforcing() returns true unconditionally
    //   on "user" (production) builds.
    //
    // Reads /sys/fs/selinux/enforce directly (selinuxfs).
    // "1" = enforcing, "0" = permissive.
    //
    // Note: ro.build.selinux is DEPRECATED — absent on
    // most devices (verified on Pixel, Samsung, Xiaomi).
    // We do not check it.
    // ──────────────────────────────────────────────

    private fun checkSeLinuxStatus(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_SELINUX, name, errors) {
            var enforceValue: String? = null

            try {
                if (NativeBridge.fileExists("/sys/fs/selinux/enforce")) {
                    enforceValue = NativeBridge.readProcFile("/sys/fs/selinux/enforce")?.trim()
                }
            } catch (_: Exception) {
                // SELinux filesystem may not be readable from app context on some devices
            }

            // "0" = permissive. On production (user) builds, AOSP compile-time locks
            // this to enforcing. Permissive mode requires a modified kernel or root.
            val suspicious = enforceValue == "0"

            evidence.add(
                Evidence(
                    checkName = CHECK_SELINUX,
                    description = when {
                        suspicious -> "SELinux is permissive — production devices are enforcing"
                        enforceValue == "1" -> "SELinux is enforcing (normal)"
                        else -> "Could not read SELinux status"
                    },
                    rawValue = "enforce=${enforceValue ?: "(unreadable)"}",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 4: Dangerous System Properties
    // Weight: 0.6
    //
    // Certain system properties indicate a device
    // running in a development or rooted state.
    // Uses the same reflection approach as
    // EmulatorDetector for reading properties.
    // ──────────────────────────────────────────────

    private fun checkDangerousSystemProperties(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        // ro.debuggable: set to "1" on eng AND userdebug builds
        // (AOSP build/core/soong_config.mk: filter userdebug eng).
        // On production "user" builds it's "0". If we see "1" on a "user"
        // build, the property was manually changed — indicates root.
        SafeExec.runCatching(CHECK_PROP_DEBUGGABLE, name, errors) {
            val debuggable = getSystemProperty("ro.debuggable")
            val buildType = Build.TYPE ?: ""
            val suspicious = debuggable == "1" &&
                !buildType.equals("userdebug", ignoreCase = true) &&
                !buildType.equals("eng", ignoreCase = true)

            evidence.add(
                Evidence(
                    checkName = CHECK_PROP_DEBUGGABLE,
                    description = if (suspicious) {
                        "ro.debuggable=1 on non-development build (Build.TYPE='$buildType')"
                    } else {
                        "ro.debuggable appears normal for build type '$buildType'"
                    },
                    rawValue = "ro.debuggable=$debuggable Build.TYPE=$buildType",
                    suspicious = suspicious,
                )
            )
        }

        // ro.secure check — "0" means adb runs as root by default
        SafeExec.runCatching(CHECK_PROP_SECURE, name, errors) {
            val secure = getSystemProperty("ro.secure")
            val suspicious = secure == "0"

            evidence.add(
                Evidence(
                    checkName = CHECK_PROP_SECURE,
                    description = if (suspicious) {
                        "ro.secure=0 — adb runs as root by default"
                    } else {
                        "ro.secure appears normal"
                    },
                    rawValue = "ro.secure=${secure.ifEmpty { "(empty)" }}",
                    suspicious = suspicious,
                )
            )
        }

        // service.adb.root check — "1" means adbd is running as root
        SafeExec.runCatching(CHECK_PROP_ADB_ROOT, name, errors) {
            val adbRoot = getSystemProperty("service.adb.root")
            val suspicious = adbRoot == "1"

            evidence.add(
                Evidence(
                    checkName = CHECK_PROP_ADB_ROOT,
                    description = if (suspicious) {
                        "service.adb.root=1 — adbd running as root"
                    } else {
                        "service.adb.root appears normal"
                    },
                    rawValue = "service.adb.root=${adbRoot.ifEmpty { "(empty)" }}",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 5: System Partition Writability
    // Hard signal
    //
    // On production devices, /system is always
    // mounted read-only. A writable /system partition
    // is a definitive indicator of root — no legitimate
    // production scenario produces this.
    // ──────────────────────────────────────────────

    private fun checkSystemPartitionWritability(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_SYSTEM_RW, name, errors) {
            var systemMountLine: String? = null
            var isRw = false

            try {
                BufferedReader(FileReader("/proc/mounts")).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        // Look for /system mount point
                        // Format: device mountpoint fstype options ...
                        val parts = line.split("\\s+".toRegex())
                        if (parts.size >= 4 && parts[1] == "/system") {
                            systemMountLine = line.trim()
                            // Options field (parts[3]) contains comma-separated flags
                            val options = parts[3].split(",")
                            isRw = options.contains("rw")
                            break
                        }
                        line = reader.readLine()
                    }
                }
            } catch (e: Exception) {
                errors.add(
                    DetectionError.FileAccessFailed(
                        detectorName = name,
                        path = "/proc/mounts",
                        cause = e,
                    )
                )
            }

            val suspicious = isRw
            evidence.add(
                Evidence(
                    checkName = CHECK_SYSTEM_RW,
                    description = if (suspicious) {
                        "/system is mounted read-write — definitive root indicator"
                    } else if (systemMountLine != null) {
                        "/system is mounted read-only (normal)"
                    } else {
                        "/system mount point not found in /proc/mounts"
                    },
                    rawValue = systemMountLine ?: "(not found)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 6: Test Keys
    // Weight: 0.4
    //
    // Production devices use "release-keys" in
    // Build.TAGS. "test-keys" indicates the firmware
    // was signed with AOSP test keys. However, some
    // custom ROMs use test-keys without being rooted,
    // so this is a weak signal.
    // ──────────────────────────────────────────────

    private fun checkTestKeys(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_TEST_KEYS, name, errors) {
            val tags = Build.TAGS ?: ""
            val suspicious = tags.contains("test-keys", ignoreCase = true)

            evidence.add(
                Evidence(
                    checkName = CHECK_TEST_KEYS,
                    description = if (suspicious) {
                        "Build.TAGS contains 'test-keys' — firmware signed with AOSP test keys"
                    } else {
                        "Build.TAGS appears normal: '$tags'"
                    },
                    rawValue = tags.ifEmpty { "(empty)" },
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 7: Magisk / KernelSU / APatch Artifacts
    // Weight: 0.8
    //
    // Modern root solutions (Magisk, KernelSU, APatch)
    // store configuration and modules under /data/adb.
    // These paths are highly specific and rarely exist
    // on non-rooted devices.
    // ──────────────────────────────────────────────

    private fun checkMagiskArtifacts(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_MAGISK_ARTIFACTS, name, errors) {
            val foundPaths = mutableListOf<String>()

            for (path in MAGISK_ARTIFACT_PATHS) {
                if (NativeBridge.fileExists(path)) {
                    foundPaths.add(path)
                }
            }

            val suspicious = foundPaths.isNotEmpty()
            evidence.add(
                Evidence(
                    checkName = CHECK_MAGISK_ARTIFACTS,
                    description = if (suspicious) {
                        "Root tool artifacts found: ${foundPaths.joinToString(", ")}"
                    } else {
                        "No Magisk/KernelSU/APatch artifacts detected"
                    },
                    rawValue = if (suspicious) foundPaths.joinToString(", ") else "(clean)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 8: OverlayFS Detection (Native)
    // Hard signal (on production builds only)
    //
    // KernelSU uses overlayfs to mount modules.
    // However, AOSP legitimately uses overlayfs on
    // userdebug/eng builds via "adb remount".
    // Source: AOSP system/core/fs_mgr/README.overlayfs.md
    // ──────────────────────────────────────────────

    private fun checkOverlayFs(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_OVERLAYFS, name, errors) {
            val result = NativeBridge.detectOverlayFs()

            // On userdebug/eng builds, overlayfs is legitimate (adb remount).
            // Only flag on production "user" builds.
            val buildType = Build.TYPE ?: ""
            val isDevelopmentBuild = buildType.equals("userdebug", ignoreCase = true) ||
                buildType.equals("eng", ignoreCase = true)
            val suspicious = result != null && !isDevelopmentBuild

            evidence.add(
                Evidence(
                    checkName = CHECK_OVERLAYFS,
                    description = if (suspicious) {
                        "Suspicious overlayfs mounts detected in /proc/self/mountinfo"
                    } else {
                        "No suspicious overlayfs mounts found"
                    },
                    rawValue = result ?: "(clean)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 9: Magisk Unix Domain Sockets (Native)
    // Soft signal — weight: 0.75
    //
    // Magisk daemon creates abstract Unix sockets
    // with 32-char random hex names for IPC.
    // Source: RootBeerFresh detection technique.
    // ──────────────────────────────────────────────

    private fun checkMagiskUnixSockets(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_MAGISK_UDS, name, errors) {
            val result = NativeBridge.detectMagiskUnixSockets()
            val suspicious = result != null

            evidence.add(
                Evidence(
                    checkName = CHECK_MAGISK_UDS,
                    description = if (suspicious) {
                        "Suspicious Unix sockets found (32+ char hex names typical of Magisk daemon)"
                    } else {
                        "No suspicious Unix domain sockets detected"
                    },
                    rawValue = result ?: "(clean)",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 10: Mount Namespace Comparison (Native)
    // Soft signal — weight: 0.7
    //
    // Root hiding tools (Shamiko, KernelSU) use
    // mount namespace isolation to unmount modules
    // from the app's view. This changes the mount
    // namespace ID vs init (PID 1).
    // ──────────────────────────────────────────────

    private fun checkMountNamespace(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_MOUNT_NS, name, errors) {
            val differs = NativeBridge.checkMountNamespaceDiff()

            evidence.add(
                Evidence(
                    checkName = CHECK_MOUNT_NS,
                    description = if (differs) {
                        "Mount namespace differs from init — root hiding (Shamiko/KernelSU) may be active"
                    } else {
                        "Mount namespace matches init (normal)"
                    },
                    rawValue = if (differs) "differs" else "matches",
                    suspicious = differs,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Check 11: APatch SuperCall Probe (Native)
    // Hard signal
    //
    // APatch registers custom syscall #45 for root.
    // Probing with an invalid key returns -EPERM if
    // APatch is present, vs normal brk behavior
    // otherwise. Safe read-only probe.
    //
    // Source: https://github.com/bmax121/APatch
    // ──────────────────────────────────────────────

    private fun checkApatchSupercall(
        evidence: MutableList<Evidence>,
        errors: MutableList<DetectionError>,
    ) {
        SafeExec.runCatching(CHECK_APATCH_SUPERCALL, name, errors) {
            val result = NativeBridge.probeSupercall()
            val suspicious = result == 1

            evidence.add(
                Evidence(
                    checkName = CHECK_APATCH_SUPERCALL,
                    description = when (result) {
                        1 -> "APatch SuperCall detected (syscall #45 returned EPERM)"
                        0 -> "APatch SuperCall not detected"
                        else -> "APatch probe inconclusive"
                    },
                    rawValue = "result=$result",
                    suspicious = suspicious,
                )
            )
        }
    }

    // ──────────────────────────────────────────────
    // Result Building
    // ──────────────────────────────────────────────

    private fun buildResult(
        evidence: List<Evidence>,
        errors: List<DetectionError>,
    ): DetectionResult {
        val confidence = computeConfidence(evidence)
        return DetectionResult(
            detected = confidence >= DETECTION_THRESHOLD,
            confidence = confidence,
            evidence = evidence,
            errors = errors,
        )
    }

    /**
     * Two-tier confidence computation:
     *
     * **Tier 1 — Hard signals (deterministic):** Signals with zero documented false
     * positives on production devices. If ANY hard signal fires, confidence is 1.0
     * immediately.
     *
     * **Tier 2 — Soft signals (heuristic):** Weighted scoring across all check groups.
     * Used as fallback when hard signals are hidden (e.g., MagiskHide/Shamiko).
     */
    private fun computeConfidence(evidence: List<Evidence>): Float {
        // Tier 1: Hard signals — any one of these = definitive root
        val hardSignalFired = evidence.any { ev ->
            ev.suspicious && ev.checkName in HARD_SIGNAL_CHECKS
        }
        if (hardSignalFired) return 1.0f

        // Tier 2: Soft signal weighted scoring
        var triggeredWeight = 0f
        val totalWeight = SOFT_CHECK_WEIGHTS.values.sum()
        if (totalWeight == 0f) return 0f

        for ((checkName, weight) in SOFT_CHECK_WEIGHTS) {
            val checkEvidence = evidence.filter { it.checkName == checkName }
            if (checkEvidence.any { it.suspicious }) {
                triggeredWeight += weight
            }
        }

        return (triggeredWeight / totalWeight).coerceIn(0f, 1f)
    }

    // ──────────────────────────────────────────────
    // Utilities
    // ──────────────────────────────────────────────

    private fun getSystemProperty(name: String): String = SystemProps.get(name)

    companion object {
        private const val DETECTION_THRESHOLD = 0.35f

        // ── Check name constants ──
        // Single source of truth for all check identifiers.
        // Used in both evidence creation and signal classification.

        // SU binary (Check 1)
        private const val CHECK_SU_BINARY = "root_su_binary"

        // Root management apps (Check 2)
        private const val CHECK_ROOT_APPS = "root_management_apps"

        // SELinux status (Check 3)
        private const val CHECK_SELINUX = "root_selinux"

        // Dangerous system properties (Check 4)
        private const val CHECK_PROP_DEBUGGABLE = "root_prop_debuggable"
        private const val CHECK_PROP_SECURE = "root_prop_secure"
        private const val CHECK_PROP_ADB_ROOT = "root_prop_adb_root"

        // System partition writability (Check 5)
        private const val CHECK_SYSTEM_RW = "root_system_rw"

        // Test keys (Check 6)
        private const val CHECK_TEST_KEYS = "root_test_keys"

        // Magisk / KernelSU / APatch artifacts (Check 7)
        private const val CHECK_MAGISK_ARTIFACTS = "root_magisk_artifacts"

        // OverlayFS detection (Check 8) — native
        private const val CHECK_OVERLAYFS = "root_overlayfs"

        // Magisk Unix domain sockets (Check 9) — native
        private const val CHECK_MAGISK_UDS = "root_magisk_uds"

        // Mount namespace comparison (Check 10) — native
        private const val CHECK_MOUNT_NS = "root_mount_namespace"

        // APatch SuperCall probe (Check 11) — native
        private const val CHECK_APATCH_SUPERCALL = "root_apatch_supercall"

        // ── Tier 1: Hard signals ──
        private val HARD_SIGNAL_CHECKS = setOf(
            CHECK_SYSTEM_RW,            // /system mounted read-write
            CHECK_OVERLAYFS,            // KernelSU overlayfs in mountinfo
            CHECK_APATCH_SUPERCALL,     // APatch custom syscall #45 responds
        )

        // ── Tier 2: Soft signals ──
        private val SOFT_CHECK_WEIGHTS = mapOf(
            CHECK_SU_BINARY to 0.7f,
            CHECK_ROOT_APPS to 0.6f,
            CHECK_SELINUX to 0.5f,
            CHECK_PROP_DEBUGGABLE to 0.6f,
            CHECK_PROP_SECURE to 0.6f,
            CHECK_PROP_ADB_ROOT to 0.6f,
            CHECK_TEST_KEYS to 0.4f,
            CHECK_MAGISK_ARTIFACTS to 0.8f,
            CHECK_MAGISK_UDS to 0.75f,
            // CHECK_MOUNT_NS removed: Zygote unshare(CLONE_NEWNS) per app means
            // all apps differ from init — would be 100% false positive rate.
        )

        // ── SU binary paths ──
        // Common locations where su binary is placed by rooting tools
        private val SU_BINARY_PATHS = listOf(
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/su/bin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/priv-app/SuperSU/SuperSU.apk",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99telekinesis",
            "/data/adb/magisk",
        )

        // ── Root management packages ──
        // Package names of known root management apps
        private val ROOT_MANAGEMENT_PACKAGES = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.kingo.root",
            "com.kingroot.kinguser",
            "me.weishu.kernelsu",
        )

        // ── Magisk / KernelSU / APatch artifact paths ──
        // Directories and files created by modern root solutions
        private val MAGISK_ARTIFACT_PATHS = listOf(
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/magisk.db",
            "/data/adb/ksu",        // KernelSU
            "/data/adb/ap",         // APatch
        )
    }
}
