import ch.ubique.uniffi.plugin.model.BuildTarget
import ch.ubique.uniffi.plugin.tasks.CargoBuildTask
import org.gradle.api.publish.maven.tasks.AbstractPublishToMaven
import org.gradle.api.tasks.bundling.Jar
import org.gradle.plugins.signing.Sign
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform")
    id("com.android.kotlin.multiplatform.library")
    id("maven-publish")
    id("signing")
    id("ch.ubique.uniffi.plugin")
}

version = findProperty("VERSION_NAME") as String
group = findProperty("GROUP") as String

val dokkaHtmlJar = tasks.register<Jar>("dokkaHtmlJar") {
    dependsOn(tasks.dokkaGeneratePublicationHtml)
    from(tasks.dokkaGeneratePublicationHtml.flatMap { it.outputDirectory })
    // Published as the javadoc jar required by Maven Central (see publishing block below).
    archiveClassifier.set("javadoc")
}

kotlin {
    jvmToolchain(25)

    // Android target
    android {
        namespace = "com.wire.crypto"
        compileSdk = libs.versions.sdk.compile.get().toInt()
        minSdk = libs.versions.sdk.min.get().toInt()

        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    // JVM target
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    // iOS targets
    iosArm64()
    iosSimulatorArm64()

    // macOS ARM64 target
    macosArm64()

    sourceSets {
        getByName("commonMain") {
            sourceSets {
                kotlin.srcDir("../shared/src/commonMain/kotlin")
            }
            dependencies {
                implementation(libs.coroutines.core)
            }
        }

        getByName("commonTest") {
            sourceSets {
                kotlin.srcDir("../shared/src/commonTest/kotlin")
            }
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.coroutines.test)
            }
        }

        getByName("jvmMain") {
            dependencies {
                implementation(libs.jna)
            }
        }

        getByName("jvmTest") {
            dependencies {
                implementation(libs.assertj.core)
            }
        }

        getByName("androidMain") {
            dependencies {
                implementation("${libs.jna.get()}@aar")
                implementation("androidx.annotation:annotation:1.9.1")
            }
        }

        getByName("androidDeviceTest") {
            dependencies {
                implementation(libs.android.junit)
                implementation(libs.espresso)
                implementation(libs.assertj.core)
            }
        }
    }
}

uniffi {
    generateFromLibrary {
        packageName = "com.wire.crypto"
    }
}

cargo {
    // Point to the crypto-ffi crate directory
    packageDirectory = layout.projectDirectory.dir("../..")

    // The Kotlin wrapper in `shared` uses the cancellable transaction API.
    features.add("cancellable-transactions")

    // Guard the keystore across processes on Apple platforms, where apps can share it with
    // their extensions. This matches the Swift bindings.
    listOf(
        BuildTarget.RustTarget.Aarch64AppleIos,
        BuildTarget.RustTarget.Aarch64AppleIosSimulator,
        BuildTarget.RustTarget.Aarch64AppleDarwin,
        BuildTarget.RustTarget.X64AppleDarwin,
    ).forEach { target ->
        compilations.named(target.name) {
            features.add("cross-process-lock")
        }
    }
}

// Without these, the iOS libraries are built for the toolchain's default deployment target.
tasks.withType<CargoBuildTask>().configureEach {
    when (rustTarget.orNull) {
        BuildTarget.RustTarget.Aarch64AppleIos -> additionalEnvironment.put("IPHONEOS_DEPLOYMENT_TARGET", "16.0")
        BuildTarget.RustTarget.Aarch64AppleIosSimulator ->
            additionalEnvironment.put("IPHONESIMULATOR_DEPLOYMENT_TARGET", "16.0")
        else -> {}
    }
}

// Strip release libraries
tasks.withType<CargoBuildTask>().configureEach {
    additionalEnvironment.putAll(release.map { if (it) mapOf("CARGO_PROFILE_RELEASE_STRIP" to "symbols") else emptyMap() })
}

afterEvaluate {
    publishing {
        publications.withType<MavenPublication>().configureEach {
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

        signing {
            useInMemoryPgpKeys(
                System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKeyId"),
                System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKey"),
                System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKeyPassword")
            )
            sign(publishing.publications)
        }
    }
}

// Allows skipping signing jars published to 'MavenLocal' repository
tasks.withType<Sign>().configureEach {
    if (System.getenv("CI") == null) {
        enabled = false
    }
}

// Every publication attaches the same dokka javadoc jar, so each publication's signing task signs
// the same file that the other publications' publish tasks consume. Gradle can't infer that
// ordering and fails the build, so make every publish task run after every signing task
// (KGP + signing plugin interaction, https://youtrack.jetbrains.com/issue/KT-46466).
tasks.withType<AbstractPublishToMaven>().configureEach {
    mustRunAfter(tasks.withType<Sign>())
}
