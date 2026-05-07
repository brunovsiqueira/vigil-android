package io.github.brunovsiqueira.vigil.util

/**
 * Reads Android system properties via reflection.
 *
 * `android.os.SystemProperties` is a hidden API. We access it via reflection
 * to read properties like `ro.kernel.qemu`, `ro.debuggable`, etc.
 */
internal object SystemProps {

    @Suppress("PrivateApi")
    fun get(name: String): String {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, name) as? String) ?: ""
        } catch (_: Exception) {
            ""
        }
    }
}
