package io.github.brunovsiqueira.vigil

/**
 * Configuration for Vigil checks.
 *
 * All detectors run by default. Use [skip] to opt out of specific categories.
 *
 * ```kotlin
 * Vigil.isDeviceSafe(context) {
 *     skip(DetectionCategory.ROOT)
 *     signingCertSha256 = "your-cert-hash"
 * }
 * ```
 */
class VigilConfig internal constructor() {

    internal val skippedCategories = mutableSetOf<DetectionCategory>()

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
     * Whether to include accelerometer/gyroscope noise analysis in emulator detection.
     * This adds ~2 seconds to the check but catches emulators with spoofed Build properties.
     * Default: true.
     */
    var includeSensorAnalysis: Boolean = true

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
