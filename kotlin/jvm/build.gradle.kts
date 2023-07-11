import org.gradle.api.tasks.testing.logging.TestExceptionFormat.*
import org.gradle.api.tasks.testing.logging.TestLogEvent.*

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("java-library")
    id("com.vanniktech.maven.publish") version "0.25.3"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
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
