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
    implementation(project(":uniffi-android"))
    implementation(platform(kotlin("bom")))
    implementation(platform(libs.coroutines.bom))
    implementation(kotlin("stdlib-jdk7"))
    implementation(libs.appCompat)
    implementation(libs.ktx.core)
    implementation(libs.coroutines.core)
    implementation(libs.slf4j)

    androidTestImplementation(kotlin("test"))
    androidTestImplementation(libs.android.logback)
    androidTestImplementation(libs.android.junit)
    androidTestImplementation(libs.espresso)
    androidTestImplementation(libs.coroutines.test)
    androidTestImplementation(libs.assertj.core)
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
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(file("proguard-android-optimize.txt"), file("proguard-rules.pro"))
        }
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    dependsOn(copyBindings)
}

tasks.withType<Jar> {
    dependsOn(copyBindings)
}

kotlin.sourceSets.getByName("main").apply {
    kotlin.srcDir(generatedDir.resolve("main"))
}

kotlin.sourceSets.getByName("androidTest").apply {
    kotlin.srcDir(generatedDir.resolve("test"))
}

// Allows skipping signing jars published to 'MavenLocal' repository
tasks.withType<Sign>().configureEach {
    if (System.getenv("CI") == null) { // i.e. not in Github Action runner
        enabled = false
    }
}
