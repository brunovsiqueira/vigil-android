# Vigil

Runtime environment integrity SDK for Android.

Vigil detects emulators, app cloning, repackaging, hooking frameworks, and root at runtime. It gives your app structured, evidence-based results so you can decide how to respond.

Fully open source. No binary blobs. No telemetry. No network calls.

## Features

- **Emulator Detection** -- 9 check groups including accelerometer/gyroscope noise analysis and GL renderer fingerprinting.
- **App Cloning Detection** -- 7 checks including ArtMethod `hotness_count` inspection (based on Matrioska, ACSAC 2024). Detects virtual containers like Parallel Space and VirtualApp.
- **App Integrity** -- Signing certificate SHA-256 verification, DEX file CRC validation, debug flag detection, and installer source verification.
- **Hooking Detection** -- Frida detection via `/proc/self/maps`, Xposed/LSPosed class probing, `rwxp` memory segment analysis, Frida port scanning, and debugger detection.
- **Root Detection** -- 11 checks including SU binaries, Magisk/KernelSU/APatch artifacts, overlayfs mount analysis, mount namespace comparison, and APatch syscall probing. Advanced checks use native C with direct syscalls.

## Design Goals

- **Two-tier confidence scoring** -- strong signals trigger immediate detection; weaker signals contribute to a weighted score. See the Architecture section for details.
- **Evidence-based reporting** -- every check returns structured `Evidence` with check name, description, raw value, and suspicion flag.
- **Modular** -- use only the detectors you need. Each implements the `TamperDetector` interface and runs independently.
- **Concurrent** -- all detectors run in parallel with independent error isolation. A failing detector degrades the verdict rather than crashing the engine.
- **Native C layer** -- critical `/proc` reads use direct syscalls (`__NR_openat`, `__NR_read`) to make hooking harder. Not foolproof, but raises the bar significantly vs Java I/O.

## Installation

### Gradle (Maven Central)

```gradle
implementation("io.github.brunovsiqueira:vigil:0.1.0")
```

**Requirements:** minSdk 24 (Android 7.0), compileSdk 36.

## Quick Start

```kotlin
// 1. Build the engine with the detectors you need
val engine = VigilEngine.Builder()
    .addDetector(EmulatorDetector(includeSensorAnalysis = true))
    .addDetector(CloningDetector())
    .addDetector(IntegrityDetector(
        expectedSigningCertSha256 = "your-cert-sha256-here",
    ))
    .addDetector(HookingDetector())
    .build()

// 2. Evaluate (suspend function -- call from a coroutine scope)
val verdict: TamperVerdict = engine.evaluate(applicationContext)

// 3. Check the overall status
when (verdict.status) {
    TamperStatus.SECURE  -> { /* Environment appears genuine */ }
    TamperStatus.WARNING -> { /* Weak signals detected */ }
    TamperStatus.TAMPERED -> { /* Strong signals detected */ }
}

// 4. Inspect per-category results and evidence
verdict.results.forEach { (category, result) ->
    result.evidence
        .filter { it.suspicious }
        .forEach { evidence ->
            Log.w("Security", "${category.displayName}: ${evidence.description}")
            Log.d("Security", "  raw=${evidence.rawValue}")
        }
}
```

To obtain your signing certificate SHA-256:

```bash
apksigner verify --print-certs app-release.apk | grep SHA-256
```

## Architecture

Vigil uses the **Strategy pattern**. Each detector implements the `TamperDetector` interface and is registered with `VigilEngine.Builder`. The engine runs all detectors concurrently via Kotlin coroutines, collects their `DetectionResult` outputs, and aggregates them into a single `TamperVerdict`.

**Scoring model:** Each detector computes confidence independently using two tiers. Tier 1 ("hard signals") are checks that the authors consider high-confidence -- if any fires, the detector's confidence is set to 1.0. Tier 2 ("soft signals") uses weighted scoring across check groups. The engine computes a weighted average across all detectors to produce the overall score, which maps to `SECURE`, `WARNING`, or `TAMPERED`. Thresholds and weights are configurable.

**Error handling:** Fail-open. Each check is wrapped in `SafeExec` so that a single failing check (e.g., permission denied) produces a `DetectionError` in the result rather than crashing the detector or the engine.

## Detection Details

### Emulator Detection (9 check groups)

| Check | Confidence | Description |
|-------|-------------|-------------|
| Build properties | Soft (0.7) | HARDWARE, FINGERPRINT, DEVICE, MODEL, PRODUCT, MANUFACTURER |
| System properties | Soft (0.6) | `ro.kernel.qemu`, `ro.hardware`, `init.svc.qemud` |
| Sensor hardware strings | High | "Goldfish" sensor name, AOSP vendor string |
| Sensor absence | Soft (0.5) | Missing step counter / significant motion sensor |
| Sensor noise analysis | Soft (0.8) | Accelerometer/gyroscope stddev below MEMS noise floor |
| Battery profile | Soft (0.85) | Temperature = 0, voltage = 0 |
| GL renderer | High | "Android Emulator", "SwiftShader", "Bluestacks" |
| File artifacts | Soft (0.6) | `/dev/qemu_pipe`, `/system/bin/qemu-props` |
| Telephony operator | Soft (0.55) | Network/SIM operator name = "Android" |

### App Cloning Detection (7 checks)

| Check | Confidence | Description |
|-------|-------------|-------------|
| Data directory path | High | Foreign package name or virtual path segments in `filesDir` |
| APK source path | High | APK loaded from `/data/data/` instead of `/data/app/` |
| `/proc/self/maps` | High | Foreign package executable artifacts in memory maps |
| Environment variables | Soft (0.7) | VirtualApp IOUniformer env vars (`V_REPLACE_ITEM`, etc.) |
| Stack trace | Soft (0.6) | Cloner class prefixes in call stack |
| Known cloner packages | Soft (0.4) | Installed cloner apps (Parallel Space, Dual Space, etc.) |
| ArtMethod hotness_count | High | `hotness_count == 0` for hot framework methods (ACSAC 2024) |

### App Integrity (4 checks)

| Check | Confidence | Description |
|-------|-------------|-------------|
| Signing certificate | High | SHA-256 mismatch = app was re-signed |
| Debug flag | Soft (0.6) | `FLAG_DEBUGGABLE` set on release build |
| Installer source | Soft (0.4) | Not installed from a known app store |
| DEX CRC | Soft (0.8) | `classes.dex` CRC32 mismatch |

### Hooking Detection (5 checks)

| Check | Confidence | Description |
|-------|-------------|-------------|
| Hooking libraries | High | Frida/Xposed/Substrate in `/proc/self/maps` |
| rwxp segments | High | Non-JIT `rwxp` memory pages (Frida GumJS/V8) |
| Frida ports | Soft (0.7) | Ports 27042/27043 open on localhost |
| Xposed classes | Soft (0.8) | `XposedBridge`, `XposedHelpers` loadable via reflection |
| Debugger | Soft (0.6) | JDWP connected or `TracerPid != 0` |

## OWASP MASVS Mapping

| Detector | MASVS Control | Related MASWE |
|----------|--------------|---------------|
| Emulator Detection | MASVS-RESILIENCE-1 | MASWE-0099 |
| App Cloning Detection | MASVS-RESILIENCE-1 | MASWE-0098 |
| App Integrity | MASVS-RESILIENCE-2 | MASWE-0067 |
| Hooking Detection | MASVS-RESILIENCE-4 | MASWE-0102 |
| Root Detection | MASVS-RESILIENCE-1 | MASWE-0097 |

## Build from Source

```bash
git clone https://github.com/brunovsiqueira/vigil-android.git
cd vigil-android
./gradlew assembleDebug
```

Requires JDK 11+, Android SDK 36, NDK 27+, and CMake 3.22.1+.

```bash
sdkmanager "platforms;android-36" "ndk;27.0.12077973" "cmake;3.22.1" "build-tools;36.0.0"
```

## Contributing

Contributions are welcome. Please open an issue before submitting large changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-check`)
3. Add tests for new detection logic
4. Ensure all tests pass (`./gradlew test`)
5. Submit a pull request with a clear description of the change and its rationale

## License

Apache License 2.0. See [LICENSE](LICENSE).

## References

- **Matrioska** -- G. Ferrara, L. Ferretti, M. Colajanni. "Matrioska: Strengthening App Repackaging Detection of Obfuscated Android Apps." ACSAC 2024 (IEEE 10917506).
- **Mascara** -- G. Ferrara, L. Ferretti, M. Colajanni. "Large-Scale Analysis of the Effectiveness of Running App Repackaging Detectors." arXiv:2010.10639.
- **ARAP** -- "A Systematic Study of Android Root/Anti-Root Solutions and Anti-Analysis Techniques." arXiv:2408.11080.
- **OWASP MASVS** -- Mobile Application Security Verification Standard. https://mas.owasp.org/MASVS/
- **OWASP MASTG** -- Mobile Application Security Testing Guide. https://mas.owasp.org/MASTG/
