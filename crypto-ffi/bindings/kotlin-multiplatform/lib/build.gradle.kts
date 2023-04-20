import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("multiplatform") version "1.8.0"
    id("com.android.library")
    id("maven-publish")
    id("kotlinx-atomicfu")
}

repositories {
    google()
    mavenCentral()
}

group = "com.wire"
version = "0.8.0-multiplatform"

val generatedDir = projectDir.resolve("generated")
val crateDir = projectDir.resolve("../../../")
val crateTargetDir = projectDir.resolve("../../../../target")
val crateTargetBindingsDir = crateDir.resolve("bindings/kotlin-native")

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
                    dependsOn(copyBinariesTasks)
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

    js(IR) {
        browser {
            testTask {
                useKarma {
                    useChromeHeadless()
                }
            }
        }
    }

    val nativeTargets = listOf(
        iosX64(),
        iosArm64(),
        macosX64(),
        macosArm64()
    )

    nativeTargets.forEach {
        configInterop(it)

        it.binaries.all {
            linkerOpts("-framework","Security")
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4")
            }
        }

        val concurrentMain by creating {
            dependsOn(commonMain)
            kotlin.srcDir(generatedDir.resolve("commonMain").resolve("kotlin"))
            dependencies {
                implementation("com.squareup.okio:okio:3.2.0")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.4.0")
            }
        }

        val commonTest by getting {
            kotlin.srcDir(generatedDir.resolve("commonTest").resolve("kotlin"))
            dependencies {
                implementation(kotlin("test"))
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4")
            }
        }
        val jvmMain by getting {
            dependsOn(concurrentMain)
            kotlin.srcDir(generatedDir.resolve("jvmMain").resolve("kotlin"))
            resources.srcDir(buildDir.resolve("processedResources").resolve("jvm").resolve("main"))
            dependencies {
                implementation("net.java.dev.jna:jna:5.12.1")
            }

        }
        val jvmTest by getting
        val jsMain by getting {
            dependencies {
                kotlin.srcDir(projectDir.resolve("externals"))
                implementation(npm("@wireapp/core-crypto", "0.7.0-rc.4", generateExternals = false))
            }
        }
        val nativeMain = sourceSets.maybeCreate("nativeMain").apply {
            dependsOn(concurrentMain)
            kotlin.srcDir(generatedDir.resolve("nativeMain").resolve("kotlin"))
        }

        val darwinMain = sourceSets.maybeCreate("darwinMain").apply {
            dependsOn(nativeMain)
        }

        val darwinTest by creating {
            dependsOn(commonTest)
        }
        val androidMain by getting {
            dependsOn(jvmMain)
        }
        val androidUnitTest by getting {
            dependsOn(jvmTest)
        }

        nativeTargets.forEach { target ->
            target.compilations.getByName("main").defaultSourceSet.dependsOn(darwinMain)
            target.compilations.getByName("test").defaultSourceSet.dependsOn(darwinTest)
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
