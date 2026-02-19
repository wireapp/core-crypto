rootProject.name = "core-crypto-kotlin"

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

include(":shared", ":jvm", ":android", ":kmp")
