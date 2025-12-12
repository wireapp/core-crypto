import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath(libs.android.tools)
        classpath(libs.kotlin.gradle)
    }
}

// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id(libs.plugins.vanniktech.publish.get().pluginId) version libs.versions.vanniktech.publish
    id(libs.plugins.dokka.get().pluginId) version libs.versions.dokka
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

subprojects {
    apply(plugin = "org.jetbrains.dokka")
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }

    tasks.withType<Test> {
        useJUnitPlatform()
        testLogging {
            events(
                TestLogEvent.PASSED,
                TestLogEvent.SKIPPED,
                TestLogEvent.FAILED,
                TestLogEvent.STANDARD_OUT,
                TestLogEvent.STANDARD_ERROR
            )
            exceptionFormat = TestExceptionFormat.FULL
            showExceptions = true
            showCauses = true
            showStackTraces = true
        }
    }

    dokka {
        moduleName.set("CoreCrypto")
        pluginsConfiguration.html {
            footerMessage.set("Copyright Wire GmbH")
        }
        dokkaSourceSets.configureEach {
            sourceLink {
                remoteUrl("https://github.com/wireapp/core-crypto/tree/main/crypto-ffi/bindings/jvm")
            }
        }
    }
}

tasks.withType<Wrapper>().configureEach {
    version = libs.versions.gradle.get()
    distributionType = Wrapper.DistributionType.BIN
}
