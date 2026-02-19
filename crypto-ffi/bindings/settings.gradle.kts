rootProject.name = "core-crypto-kotlin"

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

include(":jvm", ":android")
