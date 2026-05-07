package io.github.brunovsiqueira.vigil

import android.content.Context
import android.os.Handler
import android.os.Looper
import io.github.brunovsiqueira.vigil.detectors.CloningDetector
import io.github.brunovsiqueira.vigil.detectors.EmulatorDetector
import io.github.brunovsiqueira.vigil.detectors.HookingDetector
import io.github.brunovsiqueira.vigil.detectors.IntegrityDetector
import io.github.brunovsiqueira.vigil.detectors.RootDetector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Main entry point for Vigil environment integrity checks.
 *
 * **Simple usage** — one line, callback, works from anywhere:
 * ```kotlin
 * Vigil.isDeviceSafe(context) { safe ->
 *     if (!safe) finish()
 * }
 * ```
 *
 * **With configuration** — opt out of checks or enable deep scanning:
 * ```kotlin
 * Vigil.isDeviceSafe(context, config = {
 *     deepScan = true
 *     skip(DetectionCategory.ROOT)
 * }) { safe -> }
 * ```
 *
 * **Detailed result** — when you need per-category breakdown:
 * ```kotlin
 * Vigil.evaluate(context) { result ->
 *     result.isSafe
 *     result.details.forEach { (category, detection) -> }
 * }
 * ```
 *
 * **Kotlin coroutines** — suspend overloads for coroutine users:
 * ```kotlin
 * val safe = Vigil.isDeviceSafe(context)
 * val result = Vigil.evaluate(context)
 * ```
 */
object Vigil {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val mainHandler = Handler(Looper.getMainLooper())

    // ─── Callback API (primary — works from anywhere) ────────────

    /**
     * Checks whether the device environment is safe.
     *
     * Runs all detectors in the background and delivers the result on the main thread.
     * Safe to call from any thread, including the main thread.
     *
     * @param context Application or Activity context.
     * @param config Optional configuration block to skip categories or set parameters.
     * @param onResult Callback with `true` if the environment appears safe,
     *   `false` if tampering is detected. Always called on the main thread.
     */
    @JvmStatic
    @JvmOverloads
    fun isDeviceSafe(
        context: Context,
        config: VigilConfig.() -> Unit = {},
        onResult: (Boolean) -> Unit,
    ) {
        scope.launch {
            val result = runEvaluation(context, config)
            mainHandler.post { onResult(result.isSafe) }
        }
    }

    /**
     * Runs all detectors and delivers a detailed [VigilResult] on the main thread.
     *
     * Use this when you need per-category breakdown, confidence scores,
     * or individual evidence items.
     *
     * @param context Application or Activity context.
     * @param config Optional configuration block.
     * @param onResult Callback with the full result. Always called on the main thread.
     */
    @JvmStatic
    @JvmOverloads
    fun evaluate(
        context: Context,
        config: VigilConfig.() -> Unit = {},
        onResult: (VigilResult) -> Unit,
    ) {
        scope.launch {
            val result = runEvaluation(context, config)
            mainHandler.post { onResult(result) }
        }
    }

    // ─── Suspend API (for Kotlin coroutine users) ────────────────

    /**
     * Suspend version of [isDeviceSafe] for Kotlin coroutine users.
     *
     * ```kotlin
     * lifecycleScope.launch {
     *     val safe = Vigil.isDeviceSafe(context)
     * }
     * ```
     */
    suspend fun isDeviceSafe(
        context: Context,
        config: VigilConfig.() -> Unit = {},
    ): Boolean {
        return runEvaluation(context, config).isSafe
    }

    /**
     * Suspend version of [evaluate] for Kotlin coroutine users.
     *
     * ```kotlin
     * lifecycleScope.launch {
     *     val result = Vigil.evaluate(context)
     *     if (!result.isSafe) { /* ... */ }
     * }
     * ```
     */
    suspend fun evaluate(
        context: Context,
        config: VigilConfig.() -> Unit = {},
    ): VigilResult {
        return runEvaluation(context, config)
    }

    // ─── Internal ────────────────────────────────────────────────

    private suspend fun runEvaluation(
        context: Context,
        configure: VigilConfig.() -> Unit,
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
                includeSensorAnalysis = config.deepScan,
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
