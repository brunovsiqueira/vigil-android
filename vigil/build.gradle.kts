plugins {
    alias(libs.plugins.android.library)
    id("maven-publish")
}

android {
    namespace = "io.github.brunovsiqueira.vigil"
    compileSdk = 36

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            consumerProguardFiles("consumer-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            register<MavenPublication>("release") {
                groupId = "io.github.brunovsiqueira"
                artifactId = "vigil"
                version = "0.1.0"

                from(components["release"])

                pom {
                    name.set("Vigil")
                    description.set("Runtime environment integrity SDK for Android — detects emulators, app cloning, repackaging, hooking frameworks, and root.")
                    url.set("https://github.com/brunovsiqueira/vigil-android")

                    licenses {
                        license {
                            name.set("Apache License, Version 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }

                    developers {
                        developer {
                            id.set("brunovsiqueira")
                            name.set("Bruno Siqueira")
                            url.set("https://github.com/brunovsiqueira")
                        }
                    }

                    scm {
                        connection.set("scm:git:git://github.com/brunovsiqueira/vigil-android.git")
                        developerConnection.set("scm:git:ssh://github.com/brunovsiqueira/vigil-android.git")
                        url.set("https://github.com/brunovsiqueira/vigil-android")
                    }
                }
            }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
}
