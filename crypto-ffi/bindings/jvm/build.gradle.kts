plugins {
    kotlin("jvm")
    id("java-library")
    id("com.vanniktech.maven.publish")
    id(libs.plugins.detekt.get().pluginId) version libs.versions.detekt
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

val sharedSources = projectDir.resolve("../shared/src/commonMain")

dependencies {
    implementation(platform(kotlin("bom")))
    implementation(platform(libs.coroutines.bom))
    implementation(kotlin("stdlib-jdk7"))
    implementation(libs.jna)
    implementation(libs.coroutines.core)
    implementation(libs.kotlinx.datetime)
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.test)
    testImplementation(libs.assertj.core)
}

val buildType = if (System.getenv("RELEASE") == "1") "release" else "debug"

// This is the base directory under `build` that holds all libraries, organized by
// the build type (debug or release) and the target (linux-x86-64 etc.).
val ffiLibsBase = layout.buildDirectory.dir("ffiLibs").get().asFile

val copyFfiLibrary by tasks.registering {
    doLast {
        val libs = listOf(
            Triple("x86_64-unknown-linux-gnu", "linux-x86-64", "so"),
            Triple("aarch64-apple-darwin", "darwin-aarch64", "dylib")
        )
        libs.forEach { (rustTarget, jvmTarget, ext) ->
            val libName = "libcore_crypto_ffi.$ext"
            val src = projectDir.resolve("../../../target/$rustTarget/$buildType/$libName")
            val dest = ffiLibsBase.resolve("$buildType/$jvmTarget/$libName")
            // We try to copy all libraries. If a library does not exist and
            // we're not on CI, just skip it (presumably it does not exist because
            // we're on a different platform). However, if we're on CI, always try
            // to copy the library, which will fail if it does not exist, indicating
            // a bug in the CI setup.
            if (src.exists() || System.getenv("CI") != null) {
                src.copyTo(dest, overwrite = true)
            }
        }
    }
}

tasks.named("compileKotlin") {
    dependsOn(copyFfiLibrary)
}

sourceSets {
    main {
        kotlin {
            srcDir(sharedSources.resolve("kotlin"))
            srcDir(projectDir.resolve("src/main/uniffi"))
        }
        resources {
            srcDirs(ffiLibsBase.resolve(buildType))
        }
    }
}

// Allows skipping signing jars published to 'MavenLocal' repository
project.afterEvaluate {
    tasks.named("signMavenPublication").configure {
        if (System.getenv("CI") == null) { // i.e. not in Github Action runner
            enabled = false
        }
    }
}

detekt {
    config.setFrom(files("detekt.yml"))
}
