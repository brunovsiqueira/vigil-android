# Vigil

Runtime environment integrity SDK for Android.

Vigil detects emulators, app cloning, repackaging, hooking frameworks, and root at runtime. It gives your app structured, evidence-based verdicts so you can decide how to respond -- without binary blobs, telemetry, or closed-source dependencies.

## Features

- **Emulator Detection** -- 9 check groups including accelerometer/gyroscope noise analysis and GL renderer fingerprinting. Catches spoofed Build properties via sensor physics that cannot be faked in software.
- **App Cloning Detection** -- 7 checks including ArtMethod `hotness_count` inspection (Matrioska, ACSAC 2024). Detects virtual containers like Parallel Space and VirtualApp through filesystem, memory map, and ART runtime analysis.
- **App Integrity** -- Signing certificate SHA-256 verification, DEX file CRC validation, debug flag detection, and installer source verification. Cryptographically detects repackaged APKs.
- **Hooking Detection** -- Frida agent/gadget detection via `/proc/self/maps`, Xposed/LSPosed/EdXposed class probing, `rwxp` memory segment analysis, Frida port scanning, and JDWP/ptrace debugger detection.
- **Root Detection** -- SU binary detection, Magisk/KernelSU/APatch artifact scanning, SELinux status verification, and system partition integrity checks.

## Key Differentiators

- State-of-the-art ArtMethod `hotness_count` check (Matrioska, ACSAC 2024) -- not found in any other open-source SDK
- Two-tier confidence scoring: hard signals (deterministic, zero false positives) trigger instant detection; soft signals use weighted scoring as fallback when hard signals are spoofed
- Evidence-based reporting -- every check returns structured `Evidence` with check name, description, raw value, and suspicion flag. No opaque booleans.
- Modular architecture -- use only the detectors you need. Each implements the `TamperDetector` interface and runs independently.
- Concurrent execution -- all detectors run in parallel on `Dispatchers.Default` with independent error isolation. A failing detector degrades the verdict rather than crashing the engine.
- 100% open source. No binary blobs. No telemetry. No network calls.

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

**Scoring model:** Each detector computes confidence independently using a two-tier system. Tier 1 (hard signals) are deterministic checks with zero documented false positives -- if any fires, confidence is 1.0. Tier 2 (soft signals) uses weighted scoring across check groups as a fallback layer. The engine then computes a weighted average across all detector confidences to produce the overall score, which maps to `SECURE`, `WARNING`, or `TAMPERED`.

**Error handling:** Fail-open. Each check is wrapped in `SafeExec` so that a single failing check (e.g., permission denied) produces a `DetectionError` in the result rather than crashing the detector or the engine.

## Detection Details

### Emulator Detection (9 check groups)

| Check | Signal Tier | Description |
|-------|-------------|-------------|
| Build properties | Soft (0.7) | HARDWARE, FINGERPRINT, DEVICE, MODEL, PRODUCT, MANUFACTURER |
| System properties | Soft (0.6) | `ro.kernel.qemu`, `ro.hardware`, `init.svc.qemud` |
| Sensor hardware strings | **Hard** | "Goldfish" sensor name, AOSP vendor string |
| Sensor absence | Soft (0.5) | Missing step counter / significant motion sensor |
| Sensor noise analysis | Soft (0.8) | Accelerometer/gyroscope stddev below MEMS noise floor |
| Battery profile | Soft (0.85) | Temperature = 0, voltage = 0 |
| GL renderer | **Hard** | "Android Emulator", "SwiftShader", "Bluestacks" |
| File artifacts | Soft (0.6) | `/dev/qemu_pipe`, `/system/bin/qemu-props` |
| Telephony operator | Soft (0.55) | Network/SIM operator name = "Android" |

### App Cloning Detection (7 checks)

| Check | Signal Tier | Description |
|-------|-------------|-------------|
| Data directory path | **Hard** | Foreign package name or virtual path segments in `filesDir` |
| APK source path | **Hard** | APK loaded from `/data/data/` instead of `/data/app/` |
| `/proc/self/maps` | **Hard** | Foreign package executable artifacts in memory maps |
| Environment variables | Soft (0.7) | VirtualApp IOUniformer env vars (`V_REPLACE_ITEM`, etc.) |
| Stack trace | Soft (0.6) | Cloner class prefixes in call stack |
| Known cloner packages | Soft (0.4) | Installed cloner apps (Parallel Space, Dual Space, etc.) |
| ArtMethod hotness_count | **Hard** | `hotness_count == 0` for hot framework methods (ACSAC 2024) |

### App Integrity (4 checks)

| Check | Signal Tier | Description |
|-------|-------------|-------------|
| Signing certificate | **Hard** | SHA-256 mismatch = app was re-signed |
| Debug flag | Soft (0.6) | `FLAG_DEBUGGABLE` set on release build |
| Installer source | Soft (0.4) | Not installed from a known app store |
| DEX CRC | Soft (0.8) | `classes.dex` CRC32 mismatch |

### Hooking Detection (5 checks)

| Check | Signal Tier | Description |
|-------|-------------|-------------|
| Hooking libraries | **Hard** | Frida/Xposed/Substrate in `/proc/self/maps` |
| rwxp segments | **Hard** | Non-JIT `rwxp` memory pages (Frida GumJS/V8) |
| Frida ports | Soft (0.7) | Ports 27042/27043 open on localhost |
| Xposed classes | Soft (0.8) | `XposedBridge`, `XposedHelpers` loadable via reflection |
| Debugger | Soft (0.6) | JDWP connected or `TracerPid != 0` |

## OWASP MASVS Mapping

| Detector | MASVS Control | MASWE Weaknesses |
|----------|--------------|------------------|
| Emulator Detection | MASVS-RESILIENCE-4 | MASWE-0100 (Emulator Detection) |
| App Cloning Detection | MASVS-RESILIENCE-4 | MASWE-0100 |
| App Integrity | MASVS-RESILIENCE-2 | MASWE-0067 (Debug Detection), MASWE-0104 (Signature Verification) |
| Hooking Detection | MASVS-RESILIENCE-3 | MASWE-0101 (Reverse Engineering Detection) |
| Root Detection | MASVS-RESILIENCE-1 | MASWE-0098 (Root Detection) |

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
