plugins {
    id("com.android.library")
    id("kotlin-android")
    id("maven-publish")
}

android {
    compileSdk = 31

    defaultConfig {
        minSdk = 24
        targetSdk = 31
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(file("proguard-android-optimize.txt"), file("proguard-rules.pro"))
        }
    }
}

val generatedDir = buildDir.resolve("generated").resolve("uniffi")
val crateDir = projectDir.resolve("../../crypto-ffi/")
val crateTargetDir = projectDir.resolve("../../target")
val crateTargetBindingsDir = crateDir.resolve("bindings/kt")
val processedResourcesDir = buildDir.resolve("processedResources")

val copyBindings = tasks.register("copyBindings", Copy::class) {
    group = "uniffi"
    from(crateTargetBindingsDir)
    include("**/*")
    into(generatedDir)
}

fun registerCopyJvmBinaryTask(target: String, jniTarget: String, include: String = "*.so"): TaskProvider<Copy> =
    tasks.register("copy-${target}", Copy::class) {
        group = "uniffi"
        from(
            crateTargetDir.resolve("${target}/release"),
        )
        include(include)
        into(
            processedResourcesDir.resolve(jniTarget)
        )
    }

val copyBinariesTasks = listOf(
    registerCopyJvmBinaryTask("aarch64-linux-android", "arm64-v8a"),
    registerCopyJvmBinaryTask("armv7-linux-androideabi", "armeabi-v7a"),
    registerCopyJvmBinaryTask("i686-linux-android", "x86"),
    registerCopyJvmBinaryTask("x86_64-linux-android", "x86_64")
)

project.afterEvaluate {
    tasks.getByName("mergeReleaseJniLibFolders") {
        dependsOn(copyBinariesTasks)
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    dependsOn(copyBindings)
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

dependencies {
    implementation("net.java.dev.jna:jna:5.6.0@aar")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk7")
    implementation("androidx.appcompat:appcompat:1.4.0")
    implementation("androidx.core:core-ktx:1.7.0")
    api("org.slf4j:slf4j-api:1.7.30")

    androidTestImplementation("com.github.tony19:logback-android:2.0.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.3")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.4.0")
    androidTestImplementation(kotlin("test"))
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4")
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

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("maven") {
                groupId = "com.wire"
                artifactId = "core-crypto-android"
                version = "1.0.0-pre.6"
                from(components["release"])
                pom {
                    name.set("core-crypto-android")
                    description.set(
                            "MLS/Proteus multiplexer abstraction with encrypted persistent storage in Rust."
                    )
                    url.set("https://github.com/wireapp/core-crypto")
                    licenses {
                        license {
                            name.set("GPL-3.0")
                            url.set("https://github.com/wireapp/core-crypto/blob/main/LICENSE")
                        }
                    }
                    scm {
                        connection.set("scm:git:github.com/wireapp/core-crypto.git")
                        developerConnection.set("scm:git:ssh://github.com/wireapp/core-crypto.git")
                        url.set("https://github.com/wireapp/core-crypto")
                    }
                }
            }
        }
    }
}
