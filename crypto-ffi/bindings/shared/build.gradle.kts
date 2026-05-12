// This module holds shared Kotlin source files used by both JVM and Android modules.
// The sources are included directly by those modules rather than compiled as a separate library,
// because they depend on Uniffi-generated types that are platform-specific.

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform")
}

kotlin {
    jvmToolchain(25)

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(kotlin("stdlib"))
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("stdlib"))
            }
        }
    }
}
