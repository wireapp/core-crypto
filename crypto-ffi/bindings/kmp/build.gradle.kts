import dev.oxikt.gradle.plugin.tasks.BuildBindingsTask
import org.gradle.api.publish.maven.tasks.AbstractPublishToMaven
import org.gradle.api.tasks.bundling.Jar
import org.gradle.plugins.signing.Sign
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform")
    id("com.android.kotlin.multiplatform.library")
    id("maven-publish")
    id("signing")
    id("dev.oxikt.gradle.plugin")
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
    iosSimulatorArm64 {
        // Opening a database on iOS uses the keychain, which only apps can access. So
        // scripts/run-kmp-ios-tests.sh runs the tests inside an app, and on the simulator, an app's
        // entitlements are a section of its executable.
        binaries.getTest("DEBUG").linkerOpts(
            "-sectcreate",
            "__TEXT",
            "__entitlements",
            layout.projectDirectory.file("ios-test-host/test.entitlements").asFile.path,
        )
    }

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
                implementation(libs.kotlinx.io.core)
            }
        }

        getByName("jvmTest") {
            // The shared tests that only run on the JVM.
            kotlin.srcDir("../shared/src/jvmTest/kotlin")
        }

        getByName("jvmMain") {
            dependencies {
                implementation(libs.jna)
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

    // make builds the libraries into `target`, so that they aren't built twice.
    prebuiltLibraries = layout.projectDirectory.dir("../../../target")
}

// Stripped Linux libraries lack the metadata the bindings are generated from, so for release builds,
// make passes the unstripped library it generates its own bindings from.
providers.gradleProperty("bindingsLibrary").orNull?.let { library ->
    tasks.withType<BuildBindingsTask>().configureEach {
        libraryFile.set(layout.projectDirectory.file(library))
    }
}

// make builds OxiKT's bindgen, so that it survives clean builds and CI can share it. Pointing the
// task's input at it also drops the dependency on the task that would build it.
providers.gradleProperty("bindgen").orNull?.let { path ->
    val bindgenFile = layout.projectDirectory.file(path)
    tasks.withType<BuildBindingsTask>().configureEach {
        bindgen.set(bindgenFile)
        bindgenReadyFile.set(bindgenFile)
    }
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
