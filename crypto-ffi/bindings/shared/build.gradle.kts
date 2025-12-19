// This module holds shared Kotlin source files used by both JVM and Android modules.
// The sources are included directly by those modules rather than compiled as a separate library,
// because they depend on Uniffi-generated types that are platform-specific.

plugins {
    kotlin("multiplatform")
}

kotlin {
    jvmToolchain(17)

    jvm()

    sourceSets {
        commonMain {
            dependencies {
                implementation(kotlin("stdlib"))
            }
        }
    }
}
