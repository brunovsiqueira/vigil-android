package io.github.brunovsiqueira.vigil

/**
 * Categories of environment anomaly detection.
 * Each category groups related signals that assess a specific threat vector.
 */
enum class DetectionCategory(val displayName: String) {
    EMULATOR("Emulator Detection"),
    CLONING("App Cloning Detection"),
    INTEGRITY("App Integrity"),
    HOOKING("Hooking & Instrumentation"),
    ROOT("Root Detection"),
}
