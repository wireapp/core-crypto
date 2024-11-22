rootProject.name = "core-crypto-kotlin"

pluginManagement {
    repositories {
        google()
        mavenCentral()
    }
}

include("jvm", "android", "uniffi-jvm", "uniffi-android")
