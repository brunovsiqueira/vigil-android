# Consumer ProGuard rules for the detection SDK.
# Only keep the PUBLIC API surface — internal detection logic gets obfuscated.
# Source: https://developer.android.com/topic/performance/app-optimization/library-optimization

# Public API — main entry point
-keep class io.github.brunovsiqueira.vigil.Vigil { public *; }
-keep class io.github.brunovsiqueira.vigil.VigilConfig { public *; }
-keep class io.github.brunovsiqueira.vigil.VigilResult { *; }
-keep class io.github.brunovsiqueira.vigil.VigilResult$Companion { *; }

# Public data types exposed via VigilResult
-keep class io.github.brunovsiqueira.vigil.DetectionResult { *; }
-keep class io.github.brunovsiqueira.vigil.DetectionResult$Companion { *; }
-keep class io.github.brunovsiqueira.vigil.Evidence { *; }
-keep class io.github.brunovsiqueira.vigil.TamperStatus { *; }
-keep class io.github.brunovsiqueira.vigil.DetectionCategory { *; }
-keep class io.github.brunovsiqueira.vigil.error.DetectionError { *; }
-keep class io.github.brunovsiqueira.vigil.error.DetectionError$* { *; }

# JNI — native method names must be preserved
-keep class io.github.brunovsiqueira.vigil.detectors.ArtMethodChecker {
    native <methods>;
    *** check*(...);
}
-keep class io.github.brunovsiqueira.vigil.detectors.NativeBridge {
    native <methods>;
}

# Keep Kotlin coroutine internals needed by detectors
-keepclassmembers class * implements io.github.brunovsiqueira.vigil.TamperDetector {
    public suspend detect(android.content.Context);
}
