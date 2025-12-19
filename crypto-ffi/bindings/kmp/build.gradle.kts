import gobley.gradle.GobleyHost
import gobley.gradle.cargo.dsl.*
import org.gradle.api.tasks.bundling.Jar

plugins {
    kotlin("multiplatform")
    id("com.android.library")
    alias(libs.plugins.gobley.cargo)
    alias(libs.plugins.gobley.uniffi)
    id("com.vanniktech.maven.publish.base")
    alias(libs.plugins.kotlin.atomicfu)
}

val dokkaHtmlJar = tasks.register<Jar>("dokkaHtmlJar") {
    dependsOn(tasks.dokkaGeneratePublicationHtml)
    from(tasks.dokkaGeneratePublicationHtml.flatMap { it.outputDirectory })
    archiveClassifier.set("html-docs")
}

kotlin {
    jvmToolchain(17)

    // Android target
    androidTarget {
        publishLibraryVariants("release")
    }

    // JVM target
    jvm()

    // iOS targets
    iosArm64()
    iosSimulatorArm64()

    // macOS ARM64 target
    macosArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.coroutines.core)
            }
        }

        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.coroutines.test)
            }
        }

        val jvmMain by getting {
            dependencies {
                implementation(libs.jna)
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(libs.assertj.core)
            }
        }

        val androidMain by getting {
            dependencies {
                implementation("${libs.jna.get()}@aar")
                implementation("androidx.annotation:annotation:1.9.1")
            }
        }

        val androidInstrumentedTest by getting {
            dependencies {
                implementation(libs.android.junit)
                implementation(libs.espresso)
                implementation(libs.assertj.core)
            }
        }

        // Native targets share sources
        val nativeMain by creating {
            dependsOn(commonMain)
        }

        val nativeTest by creating {
            dependsOn(commonTest)
        }

        val iosArm64Main by getting {
            dependsOn(nativeMain)
        }

        val iosArm64Test by getting {
            dependsOn(nativeTest)
        }

        val iosSimulatorArm64Main by getting {
            dependsOn(nativeMain)
        }

        val iosSimulatorArm64Test by getting {
            dependsOn(nativeTest)
        }

        val macosArm64Main by getting {
            dependsOn(nativeMain)
        }

        val macosArm64Test by getting {
            dependsOn(nativeTest)
        }
    }
}

android {
    namespace = "com.wire.crypto"
    compileSdk = libs.versions.sdk.compile.get().toInt()

    defaultConfig {
        minSdk = libs.versions.sdk.min.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += setOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

cargo {
    // Point to the crypto-ffi crate directory
    packageDirectory = layout.projectDirectory.dir("../..")

    // Only build JVM native libraries for the current host platform
    // This disables cross-compilation for other JVM targets (e.g., Linux ARM64 on macOS)
    builds.jvm {
        embedRustLibrary = (rustTarget == GobleyHost.current.rustTarget)
    }
}

// Configure iOS build tasks with the required environment
afterEvaluate {
    tasks.matching { it.name.contains("cargoBuildIos") }.configureEach {
        // Set environment via the task's additionalEnvironment if available
        if (this is gobley.gradle.cargo.tasks.CargoBuildTask) {
            val target = if (name.contains("Simulator")) {
                "IPHONESIMULATOR_DEPLOYMENT_TARGET"
            } else {
                "IPHONEOS_DEPLOYMENT_TARGET"
            }
            additionalEnvironment.put(target, "16.0")
        }
    }
}

uniffi {
    generateFromLibrary {
        namespace = "core_crypto_ffi"
        packageName = "com.wire.crypto"
    }
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true)
    pomFromGradleProperties()
    signAllPublications()
}

// Allows skipping signing jars published to 'MavenLocal' repository
tasks.withType<Sign>().configureEach {
    if (System.getenv("CI") == null) {
        enabled = false
    }
}
