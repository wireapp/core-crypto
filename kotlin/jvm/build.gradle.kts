import org.gradle.api.tasks.testing.logging.TestExceptionFormat.*
import org.gradle.api.tasks.testing.logging.TestLogEvent.*
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("java-library")
    id("maven-publish")
    id("signing")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
    withSourcesJar()
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs += "-opt-in=kotlin.RequiresOptIn"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()

    testLogging {
        events(PASSED, SKIPPED, FAILED, STANDARD_OUT, STANDARD_ERROR)
        exceptionFormat = FULL
        showExceptions = true
        showCauses = true
        showStackTraces = true
    }
}

dependencies {
    api("org.slf4j:slf4j-api:1.7.30")
    implementation(platform(kotlin("bom")))
    implementation(kotlin("stdlib-jdk7"))
    implementation("net.java.dev.jna:jna:5.8.0")
    testImplementation("org.assertj:assertj-core:3.22.0")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.2")
    testImplementation("ch.qos.logback:logback-classic:1.2.3")
    testImplementation("ch.qos.logback:logback-core:1.2.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.2")
}

publishing {
    repositories {
        maven {
            name = "Wire"
            url = uri("../../../wire-maven/releases")
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("maven") {

                groupId = "com.wire"
                artifactId = "core-crypto-jvm"
                version = "0.2.1"

                from(components["java"])

                pom {
                    name.set("core-crypto-jvm")
                    description.set("MLS/Proteus multiplexer abstraction with encrypted persistent storage in Rust")
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
