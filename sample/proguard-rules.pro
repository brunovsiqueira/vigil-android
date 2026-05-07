# Keep only the specific entry points referenced via reflection or JNI.
# Everything else gets obfuscated by R8.
# Source: https://developer.android.com/topic/performance/app-optimization/keep-rule-examples

# JNI: native method binding requires exact class+method names
-keepclasseswithmembernames class io.github.brunovsiqueira.vigil.detectors.ArtMethodChecker {
    native <methods>;
}

# JNI: NativeBridge native methods
-keepclasseswithmembernames class io.github.brunovsiqueira.vigil.detectors.NativeBridge {
    native <methods>;
}

# Reflection: SystemProperties accessed via Class.forName
-keep class android.os.SystemProperties { *; }

# Reflection: ActivityThread accessed via Class.forName in ArtMethodChecker
-keep class android.app.ActivityThread {
    static android.app.ActivityThread currentActivityThread();
}
