import org.gradle.api.tasks.testing.logging.TestExceptionFormat.*
import org.gradle.api.tasks.testing.logging.TestLogEvent.*

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
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk7")
    implementation("net.java.dev.jna:jna:5.8.0")
    api("org.slf4j:slf4j-api:1.7.30")
    testImplementation("junit:junit:4.13.2")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine:5.8.2")
    testImplementation("ch.qos.logback:logback-classic:1.2.3")
    testImplementation("ch.qos.logback:logback-core:1.2.3")
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
                artifactId = "core-crypto-jvm"
                version = "0.6.0-pre.3"

                from(components["java"])

                pom {
                    name.set("core-crypto-jvm")
                    description.set(
                            "MLS/Proteus multiplexer abstraction with encrypted persistent storage in Rust"
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
