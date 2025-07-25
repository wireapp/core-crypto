plugins {
    kotlin("jvm")
    id("java-library")
    id("com.vanniktech.maven.publish")
    id(libs.plugins.detekt.get().pluginId) version libs.versions.detekt
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(platform(kotlin("bom")))
    implementation(platform(libs.coroutines.bom))
    implementation(kotlin("stdlib-jdk7"))
    implementation(libs.jna)
    implementation(libs.coroutines.core)
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.test)
    testImplementation(libs.assertj.core)
}

val processedResourcesDir = buildDir.resolve("processedResources")

fun registerCopyJvmBinaryTask(target: String, jniTarget: String, include: String = "*.so"): TaskProvider<Copy> =
    tasks.register<Copy>("copy-$target") {
        group = "uniffi"
        from(projectDir.resolve("../../../target/$target/release"))
        include(include)
        into(processedResourcesDir.resolve(jniTarget))
    }

val copyBinariesTasks = listOf(
    registerCopyJvmBinaryTask("x86_64-unknown-linux-gnu", "linux-x86-64"),
    registerCopyJvmBinaryTask("aarch64-apple-darwin", "darwin-aarch64", "*.dylib"),
)

tasks.withType<ProcessResources> { dependsOn(copyBinariesTasks) }

tasks.withType<Test> { dependsOn(copyBinariesTasks) }
tasks.withType<Jar> { dependsOn(copyBinariesTasks) }

sourceSets {
    main {
        kotlin {
            srcDir(projectDir.resolve("src/main/kotlin"))
            srcDir(projectDir.resolve("src/main/uniffi"))
        }
        resources {
            srcDir(processedResourcesDir)
        }
    }
}

// Allows skipping signing jars published to 'MavenLocal' repository
project.afterEvaluate {
    tasks.named("signMavenPublication").configure {
        if (System.getenv("CI") == null) { // i.e. not in Github Action runner
            enabled = false
        }
    }
}

detekt {
    config.setFrom(files("detekt.yml"))
}
