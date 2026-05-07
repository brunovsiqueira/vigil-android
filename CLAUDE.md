# Vigil Android SDK

Runtime environment integrity SDK. Detects emulators, app cloning, repackaging, hooking, and root.

## Build

```
./gradlew :vigil:assembleRelease        # library AAR
./gradlew :sample:assembleDebug         # sample app
./gradlew :vigil:test                   # unit tests
```

Requires: JDK 11+, Android SDK 36, NDK 27+, CMake 3.22.1.

## Architecture

- **Strategy pattern**: each detector implements `TamperDetector`, registered via `VigilEngine.Builder`, runs concurrently on `Dispatchers.Default`.
- **Public API**: `Vigil` object (callback + suspend). `VigilEngine`/`TamperVerdict` are `internal`.
- **Two-tier scoring**: hard signals set confidence to 1.0 immediately; soft signals use weighted scoring. Threshold at 0.35 per detector.
- **Fail-open error handling**: every check wrapped in `SafeExec.runCatching()`. Errors become `DetectionError` variants, never crashes.
- **Native C layer**: `/proc` reads use direct syscalls (`__NR_openat`/`__NR_read`) via `NativeBridge` to resist Frida hooks. File existence uses `__NR_faccessat`.

## Code style

- Checks are private methods receiving `evidence: MutableList<Evidence>` and `errors: MutableList<DetectionError>`.
- Each check wrapped in `SafeExec.runCatching(checkName, name, errors) { ... }`.
- Constants in `companion object`: `CHECK_*` for names, `HARD_SIGNAL_CHECKS` set, `SOFT_CHECK_WEIGHTS` map.
- Section dividers: `// ─── Section Name ────────────`.
- Shared utils: `SystemProps.get()` for system properties, `NativeBridge.readMapsContent()` for `/proc/self/maps`, `NativeBridge.fileExists()` for file checks.
- KDoc on public API with code examples. No redundant comments on self-explanatory code.

## Module structure

```
vigil/          SDK library (io.github.brunovsiqueira.vigil)
  detectors/    EmulatorDetector, CloningDetector, IntegrityDetector, HookingDetector, RootDetector
  error/        DetectionError sealed class
  util/         SafeExec, DetectionLogger, SystemProps
  cpp/          art_method_check.c, proc_reader.c
sample/         Demo app using Vigil API
docs/adr/       Architecture Decision Records (ADR-001 through ADR-008)
tools/          Frida bypass scripts for attacker-perspective testing
```

## Public API surface

- `Vigil` object (callback + suspend). This is the only entry point consumers use.
- `VigilConfig`, `VigilResult`, `DetectionResult`, `Evidence`, `TamperStatus`, `DetectionCategory`, `DetectionError`.
- Everything else (`VigilEngine`, `TamperVerdict`, detectors, `NativeBridge`) is `internal`. Don't expose them.

## Key constraints

- Never crash the host app. Detectors fail-open; errors are reported, not thrown.
- No network calls. No telemetry. No binary blobs.
- Read `/proc` files via `NativeBridge` (direct syscalls), not Java I/O.
- File existence checks via `NativeBridge.fileExists()`, not `File.exists()`.
- Read `/proc/self/maps` once per detector, reuse content. Do not call `scanMapsForPattern()` per pattern.
- `Vigil` object owns threading. Callback API delivers on main thread. Consumers never need to think about threads.
- Sensor noise analysis off by default (`deepScan = false`). Default check completes in ~100ms.

## Detection design decisions

- **Positive-only for inconclusive checks**: if a check can't run (e.g., ArtMethod on unsupported API, jmethodID is indirect on Samsung), return `Inconclusive` — never "clean". Absence of signal is not evidence of safety.
- **Executable-extension filter on /proc/self/maps**: flag foreign paths only if they end in `.apk/.dex/.so/.odex/.vdex/.oat/.art`. Non-executable files (fonts, configs mapped by GMS) are benign. Do not whitelist by package name — breaks on Chinese OEM devices.
- **Attacker-perspective testing**: `tools/` contains Frida bypass scripts that simulate real attacks. Use them to validate that detection survives hooking.

## Don't

- Don't use `File.exists()` — use `NativeBridge.fileExists()`.
- Don't read `/proc` via Java I/O — use `NativeBridge.readMapsContent()` or `readProcFile()`.
- Don't throw exceptions from detectors — wrap in `SafeExec`, return `DetectionError`.
- Don't add public classes — the API surface is intentionally small.
- Don't duplicate `getSystemProperty()` — use `SystemProps.get()`.
