package io.github.brunovsiqueira.vigil.detectors

import android.util.Log
import java.io.BufferedReader
import java.io.FileReader

internal object NativeBridge {
    private const val TAG = "NativeBridge"

    var isLoaded: Boolean = false
        private set

    init {
        try {
            System.loadLibrary("vigil_native")
            isLoaded = true
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native library not available: ${e.message}")
        }
    }

    external fun readProcMaps(): String?
    external fun scanMapsForPattern(pattern: String): Boolean
    external fun fileExistsNative(path: String): Boolean

    // Advanced root detection via direct syscalls
    external fun readProcFile(path: String): String?
    external fun detectOverlayFs(): String?
    external fun detectMagiskUnixSockets(): String?
    external fun checkMountNamespaceDiff(): Boolean
    external fun probeSupercall(): Int  // 0=not present, 1=detected, -1=error

    /**
     * Reads /proc/self/maps once using native syscalls (preferred) or Java fallback.
     * All callers that need maps content should use this instead of reading the file directly.
     */
    fun readMapsContent(): String? {
        return if (isLoaded) {
            readProcMaps()
        } else {
            try {
                BufferedReader(FileReader("/proc/self/maps")).use { it.readText() }
            } catch (_: Exception) {
                null
            }
        }
    }

    /**
     * Checks file existence via native direct syscall (bypasses libc hooks) or Java fallback.
     */
    fun fileExists(path: String): Boolean {
        return if (isLoaded) {
            fileExistsNative(path)
        } else {
            try {
                java.io.File(path).exists()
            } catch (_: Exception) {
                false
            }
        }
    }
}
