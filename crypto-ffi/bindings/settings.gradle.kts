rootProject.name = "core-crypto-kotlin"

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

include(":shared", ":jvm", ":android", ":kmp")

// for multiplatform projects the artifact id is tied name
project(":kmp").name = "core-crypto-kmp"
