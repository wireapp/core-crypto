import org.gradle.api.tasks.bundling.Jar

plugins {
    alias(libs.plugins.android.library)
    kotlin("android")
    id("maven-publish")
    id("signing")
}

val sharedSources = projectDir.resolve("../shared/src/commonMain")
val sharedTestSources = projectDir.resolve("../shared/src/commonTest")

version = findProperty("VERSION_NAME") as String
group = findProperty("GROUP") as String

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
                    srcDir(sharedSources.resolve("kotlin"))
                }
            }
            androidTest {
                kotlin {
                    srcDir(sharedTestSources.resolve("kotlin"))
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
                artifactId = findProperty("POM_ARTIFACT_ID") as String

                // We replace regular javadoc with dokka html docs since we are running into this bug:
                // https://youtrack.jetbrains.com/issue/KT-60197/Dokka-JDK-17-PermittedSubclasses-requires-ASM9-during-compilation
                artifact(tasks.named("dokkaHtmlJar"))

                pom {
                    name.set(findProperty("POM_NAME") as String)
                    description.set(findProperty("POM_DESCRIPTION") as String)
                    url.set(findProperty("POM_URL") as String)

                    licenses {
                        license {
                            name.set(findProperty("POM_LICENSE_NAME") as String)
                            url.set(findProperty("POM_LICENSE_URL") as String)
                            distribution.set(findProperty("POM_LICENSE_DIST") as String)
                        }
                    }

                    scm {
                        url.set(findProperty("POM_SCM_URL") as String)
                        connection.set(findProperty("POM_SCM_CONNECTION") as String)
                        developerConnection.set(findProperty("POM_SCM_DEV_CONNECTION") as String)
                    }

                    developers {
                        developer {
                            name.set(findProperty("POM_DEVELOPER_NAME") as String)
                            email.set(findProperty("POM_DEVELOPER_EMAIL") as String)
                        }
                    }
                }
            }
        }
    }
    signing {
        useInMemoryPgpKeys(
            System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKeyId"),
            System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKey"),
            System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKeyPassword")
        )
        sign(publishing.publications)
    }
}
