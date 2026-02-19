rootProject.name = "core-crypto-kotlin"

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    plugins {
        id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
    }
}

include(":shared", ":jvm", ":android", ":kmp")
