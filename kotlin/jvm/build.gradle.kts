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
    registerCopyJvmBinaryTask("x86_64-unknown-linux-gnu", "linux-x86-64"),
    registerCopyJvmBinaryTask("aarch64-apple-darwin", "darwin-aarch64", "*.dylib"),
    registerCopyJvmBinaryTask("x86_64-apple-darwin", "darwin-x86-64", "*.dylib"),
)

tasks.withType<ProcessResources> {
    dependsOn(copyBinariesTasks)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    dependsOn(copyBindings)
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

kotlin.sourceSets.getByName("main").apply {
    kotlin.srcDir(generatedDir.resolve("main"))
}

kotlin.sourceSets.getByName("test").apply {
    kotlin.srcDir(generatedDir.resolve("test"))
}

sourceSets {
    main {
        resources {
            srcDir(processedResourcesDir)
        }
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
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4")
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
                version = "1.0.0-pre.6+v1-schemafix-004"

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
