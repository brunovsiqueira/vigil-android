package io.github.brunovsiqueira.vigil

import io.github.brunovsiqueira.vigil.error.DetectionError

/**
 * Result of a Vigil environment check.
 *
 * For most apps, [isSafe] is the only field you need.
 * Use [details] for per-category breakdown when you need more control.
 *
 * @property isSafe `true` if no tampering was detected. Equivalent to `status == TamperStatus.SECURE`.
 * @property status The aggregated trust level: SECURE, WARNING, or TAMPERED.
 * @property score Aggregated confidence score (0.0 = fully trusted, 1.0 = definitely tampered).
 * @property durationMs Total wall-clock time for all checks in milliseconds.
 * @property details Per-category results. Only populated when [Vigil.evaluate] is used.
 * @property errors Non-fatal errors encountered during detection (e.g., permission denied).
 */
data class VigilResult(
    val isSafe: Boolean,
    val status: TamperStatus,
    val score: Float,
    val durationMs: Long,
    val details: Map<DetectionCategory, DetectionResult>,
    val errors: List<DetectionError>,
) {
    companion object {
        internal fun from(verdict: TamperVerdict): VigilResult = VigilResult(
            isSafe = verdict.status == TamperStatus.SECURE,
            status = verdict.status,
            score = verdict.overallScore,
            durationMs = verdict.durationMs,
            details = verdict.results,
            errors = verdict.errors,
        )
    }
}
