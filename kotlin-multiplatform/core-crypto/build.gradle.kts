import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.library")
    id("maven-publish")
}

group = "com.wire"
version = "0.6.0-rc.3-multiplatform"

val generatedDir = buildDir.resolve("generated").resolve("uniffi")
val crateDir = projectDir.resolve("../../crypto-ffi/")
val crateTargetDir = projectDir.resolve("../../target")
val crateTargetBindingsDir = crateDir.resolve("bindings/kotlin-native")

val copyBindings = tasks.register("copyBindings", Copy::class) {
    group = "uniffi"
    from(crateTargetBindingsDir)
    into(generatedDir)
}

fun registerCopyAndroidBinaryTask(target: String, jniTarget: String): TaskProvider<Copy> =
    tasks.register("copy-${target}", Copy::class) {
        group = "uniffi"
        from(
            crateTargetDir.resolve("${target}/release"),
        )
        include("*.so")
        into(
            buildDir.resolve("androidMain").resolve("main").resolve("jniLibs").resolve(jniTarget)
        )
    }

fun registerCopyJvmBinaryTask(target: String, jniTarget: String, include: String = "*.so"): TaskProvider<Copy> =
    tasks.register("copy-${target}", Copy::class) {
        group = "uniffi"
        from(
            crateTargetDir.resolve("${target}/release"),
        )
        include(include)
        into(
            buildDir.resolve("processedResources").resolve("jvm").resolve("main").resolve(jniTarget)
        )
    }

val copyBinariesTasks = listOf(
    registerCopyJvmBinaryTask("x86_64-unknown-linux-gnu", "linux-x86-64"),
    registerCopyJvmBinaryTask("aarch64-apple-darwin", "darwin-aarch64", "*.dylib"),
    registerCopyJvmBinaryTask("x86_64-apple-darwin", "darwin-x86-64", "*.dylib"),
    registerCopyAndroidBinaryTask("aarch64-linux-android", "arm64-v8a"),
    registerCopyAndroidBinaryTask("i686-linux-android", "x86"),
    registerCopyAndroidBinaryTask("x86_64-linux-android", "x86_64"),
    registerCopyAndroidBinaryTask("armv7-linux-androideabi", "armeabi-v7a")
)

tasks.withType<ProcessResources> {
    dependsOn(copyBinariesTasks)
}

tasks.withType<KotlinCompile> {
    dependsOn(copyBindings)
}

repositories {
    mavenCentral()
}

fun configInterop(target: org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget) {
    target.compilations.getByName("main") {
        cinterops {
            val uniffi by creating {
                packageName("com.wire.crypto.cinterop")
                header(
                    generatedDir.resolve("nativeInterop").resolve("cinterop").resolve("headers").resolve("CoreCrypto").resolve("CoreCrypto.h")
                )
                tasks.named(interopProcessingTaskName) {
                    dependsOn(copyBinariesTasks, copyBindings)
                }
                defFile(projectDir.resolve(("src/nativeInterop/cinterop/uniffi.def")))
            }
        }
    }
}

kotlin {
    android() {
        publishLibraryVariants("release")
    }
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }

    val nativeTargets = listOf(
        iosX64(),
        iosArm64(),
        macosX64(),
        macosArm64(),
        linuxX64()
    )

    nativeTargets.forEach {
        configInterop(it)

        it.binaries.all {
            linkerOpts("-framework","Security")
        }
    }

    sourceSets {
        val commonMain by getting {
            kotlin.srcDir(generatedDir.resolve("commonMain").resolve("kotlin"))
            dependencies {
                implementation("com.squareup.okio:okio:3.2.0")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.4.0")
            }

        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            kotlin.srcDir(generatedDir.resolve("jvmMain").resolve("kotlin"))
            dependencies {
                implementation("net.java.dev.jna:jna:5.12.1")
            }

        }
        val jvmTest by getting
        val nativeMain = sourceSets.maybeCreate("nativeMain").apply {
            kotlin.srcDir(generatedDir.resolve("nativeMain").resolve("kotlin"))
        }
        val nativeTest = sourceSets.maybeCreate("nativeTest")
        val androidMain by getting {
            dependsOn(jvmMain)
        }
        val androidTest by getting

        nativeTargets.forEach { target ->
            target.compilations.getByName("main").defaultSourceSet.dependsOn(nativeMain)
            target.compilations.getByName("test").defaultSourceSet.dependsOn(nativeTest)
        }
    }
}

android {
    compileSdk = 33
    defaultConfig {
        minSdk = 24
    }
    sourceSets {
        getByName("main").jniLibs.srcDirs(buildDir.resolve("androidMain").resolve("main").resolve("jniLibs"))
    }
}

publishing {
    repositories {
        maven {
            name = "GitHub"
            url = uri("https://maven.pkg.github.com/wireapp/core-crypto")
            credentials {
                username =
                    project.findProperty("gpr.user") as String? ?: System.getenv("GITHUB_ACTOR")
                password =
                    project.findProperty("gpr.key") as String? ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}

// Workaround for https://youtrack.jetbrains.com/issue/KT-51970
afterEvaluate {
    afterEvaluate {
        tasks.configureEach {
            if (
                name.startsWith("compile")
                && name.endsWith("KotlinMetadata")
            ) {
                println("disabling $name")
                enabled = false
            }
        }
    }
}
