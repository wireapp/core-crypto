// This module holds shared Kotlin source files used by both JVM and Android modules.
// The sources are included directly by those modules rather than compiled as a separate library,
// because they depend on Uniffi-generated types that are platform-specific.

import dev.detekt.gradle.extensions.FailOnSeverity
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform")
    id(libs.plugins.detekt.get().pluginId) version libs.versions.detekt
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

detekt {
    source.setFrom(files("src/commonMain/kotlin", "src/commonTest/kotlin"))
    buildUponDefaultConfig = true
    config.setFrom(files("../detekt.yml"))
    failOnSeverity = FailOnSeverity.Info
}
