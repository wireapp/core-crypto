rootProject.name = "core-crypto-kotlin"

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

val androidEnabled = System.getenv("ANDROID_HOME") != null

include(":shared", ":jvm")

if (androidEnabled) {
    include(":android", ":kmp")

    // for multiplatform projects the artifact id is tied to the name
    project(":kmp").name = "core-crypto-kmp"
}
