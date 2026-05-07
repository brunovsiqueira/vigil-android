package io.github.brunovsiqueira.vigil

/**
 * Configuration for Vigil checks.
 *
 * All detectors run by default. Use [skip] to opt out of specific categories.
 * Sensor noise analysis is off by default for fast checks (~100ms).
 * Enable [deepScan] for thorough emulator detection (~2.5s).
 *
 * ```kotlin
 * Vigil.isDeviceSafe(context) { safe ->
 *     // all checks, fast by default
 * }
 *
 * Vigil.isDeviceSafe(context, config = {
 *     deepScan = true
 *     signingCertSha256 = "your-cert-hash"
 * }) { safe -> }
 * ```
 */
class VigilConfig internal constructor() {

    internal val skippedCategories = mutableSetOf<DetectionCategory>()

    /**
     * When `true`, includes accelerometer/gyroscope noise analysis in emulator detection.
     * This adds ~2 seconds but catches emulators that spoof Build properties.
     * Default: `false` (fast mode).
     */
    var deepScan: Boolean = false

    /**
     * Expected SHA-256 hash of the app's signing certificate.
     * When set, the integrity detector verifies the APK signature matches.
     * When null (default), the signing certificate check is skipped.
     *
     * Obtain via: `apksigner verify --print-certs app-release.apk | grep SHA-256`
     */
    var signingCertSha256: String? = null

    /**
     * Expected CRC32 values for DEX files (e.g., `mapOf("classes.dex" to 0x1A2B3C4DL)`).
     * When empty (default), the DEX integrity check is skipped.
     */
    var expectedDexCrcs: Map<String, Long> = emptyMap()

    /**
     * Opt out of a detection category. All categories run by default.
     *
     * ```kotlin
     * skip(DetectionCategory.ROOT)
     * skip(DetectionCategory.EMULATOR)
     * ```
     */
    fun skip(category: DetectionCategory) {
        skippedCategories.add(category)
    }
}
