package io.github.brunovsiqueira.vigil.detectors

import android.util.Log

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
}
