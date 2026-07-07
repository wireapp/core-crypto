rootProject.name = "core-crypto-kotlin"

pluginManagement {
    includeBuild("../../../gobley/build-logic")
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

includeBuild("../../../gobley/build-logic") {
    dependencySubstitution {
        val projectNames = arrayOf(
            "gobley-gradle",
            "gobley-gradle-cargo",
            "gobley-gradle-rust",
            "gobley-gradle-uniffi",
        )
        for (projectName in projectNames) {
            substitute(module("dev.gobley.uniffi:$projectName"))
                .using(project(":$projectName"))
        }
    }
}

val androidEnabled = System.getenv("ANDROID_HOME") != null

include(":shared", ":jvm")

if (androidEnabled) {
    include(":android", ":kmp")

    // for multiplatform projects the artifact id is tied to the name
    project(":kmp").name = "core-crypto-kmp"
}
