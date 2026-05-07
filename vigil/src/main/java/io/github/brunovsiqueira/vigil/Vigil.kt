package io.github.brunovsiqueira.vigil

import android.content.Context
import io.github.brunovsiqueira.vigil.detectors.CloningDetector
import io.github.brunovsiqueira.vigil.detectors.EmulatorDetector
import io.github.brunovsiqueira.vigil.detectors.HookingDetector
import io.github.brunovsiqueira.vigil.detectors.IntegrityDetector
import io.github.brunovsiqueira.vigil.detectors.RootDetector
import kotlinx.coroutines.runBlocking

/**
 * Main entry point for Vigil environment integrity checks.
 *
 * **Simple usage** — one line, all detectors, boolean result:
 * ```kotlin
 * val safe = Vigil.isDeviceSafe(context)
 * ```
 *
 * **With configuration** — opt out of specific checks:
 * ```kotlin
 * val safe = Vigil.isDeviceSafe(context) {
 *     skip(DetectionCategory.ROOT)
 *     signingCertSha256 = "your-cert-sha256"
 * }
 * ```
 *
 * **Detailed result** — when you need per-category breakdown:
 * ```kotlin
 * val result = Vigil.evaluate(context)
 * if (!result.isSafe) {
 *     result.details.forEach { (category, detection) ->
 *         // inspect per-category evidence
 *     }
 * }
 * ```
 *
 * **Blocking (Java interop):**
 * ```kotlin
 * val safe = Vigil.isDeviceSafeSync(context)
 * ```
 */
object Vigil {

    /**
     * Checks whether the device environment is safe.
     *
     * Runs all detectors concurrently and returns `true` if no tampering is detected.
     * This is a suspend function — call from a coroutine scope.
     *
     * @param context Application or Activity context.
     * @param configure Optional configuration block to skip categories or set parameters.
     * @return `true` if the environment appears safe, `false` if tampering is detected.
     */
    suspend fun isDeviceSafe(
        context: Context,
        configure: VigilConfig.() -> Unit = {},
    ): Boolean {
        return evaluate(context, configure).isSafe
    }

    /**
     * Blocking version of [isDeviceSafe] for Java interop or non-coroutine contexts.
     *
     * Runs all detectors and blocks the calling thread until complete.
     * Do not call on the main thread — this will cause an ANR.
     *
     * @param context Application or Activity context.
     * @param configure Optional configuration block.
     * @return `true` if the environment appears safe, `false` if tampering is detected.
     */
    fun isDeviceSafeSync(
        context: Context,
        configure: VigilConfig.() -> Unit = {},
    ): Boolean {
        return runBlocking { isDeviceSafe(context, configure) }
    }

    /**
     * Runs all detectors and returns a detailed [VigilResult].
     *
     * Use this when you need per-category breakdown, confidence scores,
     * or individual evidence items. For a simple boolean, use [isDeviceSafe].
     *
     * @param context Application or Activity context.
     * @param configure Optional configuration block.
     * @return A [VigilResult] with overall status, score, and per-category details.
     */
    suspend fun evaluate(
        context: Context,
        configure: VigilConfig.() -> Unit = {},
    ): VigilResult {
        val config = VigilConfig().apply(configure)
        val engine = buildEngine(config)
        val verdict = engine.evaluate(context)
        return VigilResult.from(verdict)
    }

    private fun buildEngine(config: VigilConfig): VigilEngine {
        val builder = VigilEngine.Builder()

        if (DetectionCategory.EMULATOR !in config.skippedCategories) {
            builder.addDetector(EmulatorDetector(
                includeSensorAnalysis = config.includeSensorAnalysis,
            ))
        }

        if (DetectionCategory.CLONING !in config.skippedCategories) {
            builder.addDetector(CloningDetector())
        }

        if (DetectionCategory.INTEGRITY !in config.skippedCategories) {
            builder.addDetector(IntegrityDetector(
                expectedSigningCertSha256 = config.signingCertSha256 ?: "",
                expectedDexCrcs = config.expectedDexCrcs,
            ))
        }

        if (DetectionCategory.HOOKING !in config.skippedCategories) {
            builder.addDetector(HookingDetector())
        }

        if (DetectionCategory.ROOT !in config.skippedCategories) {
            builder.addDetector(RootDetector())
        }

        return builder.build()
    }
}
