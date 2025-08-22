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
    implementation(libs.ktx.core)
    implementation(libs.coroutines.core)

    androidTestImplementation(kotlin("test"))
    androidTestImplementation(libs.android.logback)
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
}

val processedResourcesDir = layout.buildDirectory.dir("processedResources").get().asFile

fun registerCopyJvmBinaryTask(target: String, jniTarget: String, include: String = "*.so"): TaskProvider<Copy> =
    tasks.register<Copy>("copy-$target") {
        group = "uniffi"
        from(projectDir.resolve("../../../target/$target/release"))
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
