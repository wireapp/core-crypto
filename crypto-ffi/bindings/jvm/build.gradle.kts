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

dependencies {
    implementation(platform(kotlin("bom")))
    implementation(platform(libs.coroutines.bom))
    implementation(kotlin("stdlib-jdk7"))
    implementation(libs.jna)
    implementation(libs.coroutines.core)
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
        val osName = System.getProperty("os.name")
        val (rustTarget, jvmTarget, ext) = if (osName == "Linux") {
            Triple("x86_64-unknown-linux-gnu", "linux-x86-64", "so")
        } else {
            Triple("aarch64-apple-darwin", "darwin-aarch64", "dylib")
        }

        val libName = "libcore_crypto_ffi.$ext"
        val src = projectDir.resolve("../../../target/$rustTarget/$buildType/$libName")
        val dest = ffiLibsBase.resolve("$buildType/$jvmTarget/$libName")
        src.copyTo(dest, overwrite = true)
    }
}

tasks.named("compileKotlin") {
    dependsOn(copyFfiLibrary)
}

sourceSets {
    main {
        kotlin {
            srcDir(projectDir.resolve("src/main/kotlin"))
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
