import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.jvm.tasks.Jar

plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish")
}

val kotlinSources = projectDir.resolve("../jvm/src")
val generatedDir = buildDir.resolve("generated").resolve("uniffi")

val copyBindings by tasks.register<Copy>("copyBindings") {
    group = "uniffi"
    from(kotlinSources)
    include("**/*")
    into(generatedDir)
}

dependencies {
    api(platform(kotlin("bom")))
    api(platform(libs.coroutines.bom))
    api(kotlin("stdlib-jdk7"))
    api("${libs.jna.get()}@aar")
    api(libs.appCompat)
    api(libs.ktx.core)
    api(libs.coroutines.core)
    api(libs.slf4j)
    testImplementation(kotlin("test"))
    testImplementation(libs.android.logback)
    testImplementation(libs.android.junit)
    testImplementation(libs.espresso)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.assertj.core)
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

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(file("proguard-android-optimize.txt"), file("proguard-rules.pro"))
        }
    }
}

val processedResourcesDir = buildDir.resolve("processedResources")

fun registerCopyJvmBinaryTask(target: String, jniTarget: String, include: String = "*.so"): TaskProvider<Copy> =
    tasks.register<Copy>("copy-${target}") {
        group = "uniffi"
        from(projectDir.resolve("../../../target/${target}/release"))
        include(include)
        into(processedResourcesDir.resolve(jniTarget))
    }

val copyBinariesTasks = listOf(
    registerCopyJvmBinaryTask("aarch64-linux-android", "arm64-v8a"),
    registerCopyJvmBinaryTask("armv7-linux-androideabi", "armeabi-v7a"),
    registerCopyJvmBinaryTask("i686-linux-android", "x86"),
    registerCopyJvmBinaryTask("x86_64-linux-android", "x86_64")
)

project.afterEvaluate {
    tasks.getByName("mergeReleaseJniLibFolders") { dependsOn(copyBinariesTasks) }
    tasks.getByName("mergeDebugJniLibFolders") { dependsOn(copyBinariesTasks) }
}

tasks.withType<ProcessResources> {
    dependsOn(copyBinariesTasks)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    dependsOn(copyBindings)
}

tasks.withType<Jar> {
    dependsOn(copyBindings)
}

tasks.withType<Test> {
    enabled = false // FIXME: find a way to do this at some point
    dependsOn(copyBinariesTasks)
}

kotlin.sourceSets.getByName("main").apply {
    kotlin.srcDir(generatedDir.resolve("main"))
}

kotlin.sourceSets.getByName("androidTest").apply {
    kotlin.srcDir(generatedDir.resolve("test"))
}

android.sourceSets.getByName("main").apply {
    jniLibs.srcDir(processedResourcesDir)
}

// Allows skipping signing jars published to 'MavenLocal' repository
tasks.withType<Sign>().configureEach {
    if (System.getenv("CI") == null) { // i.e. not in Github Action runner
        enabled = false
    }
}
