plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish")
}

dependencies {
    implementation(platform(kotlin("bom")))
    implementation(platform(libs.coroutines.bom))
    implementation(kotlin("stdlib-jdk7"))
    implementation("${libs.jna.get()}@aar")
    implementation(libs.appCompat)
    implementation(libs.ktx.core)
    implementation(libs.coroutines.core)
    implementation(libs.slf4j)
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
    registerCopyJvmBinaryTask("x86_64-linux-android", "x86_64")
)

project.afterEvaluate {
    tasks.getByName("mergeReleaseJniLibFolders") { dependsOn(copyBinariesTasks) }
    tasks.getByName("mergeDebugJniLibFolders") { dependsOn(copyBinariesTasks) }
}

tasks.withType<ProcessResources> {
    dependsOn(copyBinariesTasks)
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
