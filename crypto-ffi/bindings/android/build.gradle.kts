import org.gradle.api.tasks.bundling.Jar

plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish.base")
}

val jvmSources = projectDir.resolve("../jvm/src")

val dokkaHtmlJar = tasks.register<Jar>("dokkaHtmlJar") {
    dependsOn(tasks.dokkaGeneratePublicationHtml)
    from(tasks.dokkaGeneratePublicationHtml.flatMap { it.outputDirectory })
    archiveClassifier.set("html-docs")
}

dependencies {
    implementation(platform(kotlin("bom")))
    implementation(platform(libs.coroutines.bom))
    implementation(kotlin("stdlib-jdk7"))
    implementation("${libs.jna.get()}@aar")
    implementation(libs.coroutines.core)
    implementation(libs.kotlinx.datetime)
    implementation("androidx.annotation:annotation:1.9.1")

    androidTestImplementation(kotlin("test"))
    androidTestImplementation(libs.android.junit)
    androidTestImplementation(libs.espresso)
    androidTestImplementation(libs.coroutines.test)
    androidTestImplementation(libs.assertj.core)
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true)
    pomFromGradleProperties()
    signAllPublications()
}

val targets = listOf(
    "aarch64-linux-android" to "arm64-v8a",
    "armv7-linux-androideabi" to "armeabi-v7a",
    "x86_64-linux-android" to "x86_64"
)

// This is the base directory under `build` that holds all libraries, organized by
// the build type (debug or release) and the Android target (arm64-v8a etc.).
// Libraries are copied there during the preDebugBuild and preReleaseBuild tasks.
val ffiLibsBase = layout.buildDirectory.dir("ffiLibs").get().asFile

fun copyFfiLibraries(buildType: String) {
    for ((rustTarget, androidTarget) in targets) {
        val src = projectDir.resolve("../../../target/$rustTarget/$buildType/libcore_crypto_ffi.so")
        val dest = ffiLibsBase.resolve("$buildType/$androidTarget/libcore_crypto_ffi.so")
        src.copyTo(dest, overwrite = true)
    }
}

tasks.matching { it.name == "preDebugBuild" }.configureEach {
    doLast {
        copyFfiLibraries("debug")
    }
}

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    doLast {
        copyFfiLibraries("release")
    }
}

android {
    namespace = "com.wire.crypto"

    compileSdk = libs.versions.sdk.compile.get().toInt()
    defaultConfig {
        minSdk = libs.versions.sdk.min.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        jvmToolchain(17)
        sourceSets {
            main {
                kotlin {
                    srcDir(projectDir.resolve("src/main/uniffi"))
                    srcDir(jvmSources.resolve("main/kotlin"))
                }
            }
            androidTest {
                kotlin {
                    srcDir(jvmSources.resolve("test"))
                }
            }
        }
    }

    sourceSets {
        getByName("debug") {
            jniLibs {
                srcDirs(ffiLibsBase.resolve("debug"))
            }
        }

        getByName("release") {
            jniLibs {
                srcDirs(ffiLibsBase.resolve("release"))
            }
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(file("proguard-android-optimize.txt"), file("proguard-rules.pro"))
        }
    }

    testBuildType = if (System.getenv("RELEASE") == "1") "release" else "debug"
}

// Allows skipping signing jars published to 'MavenLocal' repository
tasks.withType<Sign>().configureEach {
    if (System.getenv("CI") == null) { // i.e. not in Github Action runner
        enabled = false
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("library") {
                from(components["release"])
                // We replace regular javadoc with dokka html docs since we are running into this bug:
                // https://youtrack.jetbrains.com/issue/KT-60197/Dokka-JDK-17-PermittedSubclasses-requires-ASM9-during-compilation
                artifact(tasks.named("dokkaHtmlJar"))
            }
        }
    }
}
