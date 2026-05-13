import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    id("java-library")
    id("maven-publish")
    id("signing")
    id(libs.plugins.detekt.get().pluginId) version libs.versions.detekt
    id("me.champeau.jmh") version "0.7.3"
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(25)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

val sharedSources = projectDir.resolve("../shared/src/commonMain")
val sharedTestSources = projectDir.resolve("../shared/src/commonTest")

dependencies {
    implementation(platform(libs.coroutines.bom))
    implementation(libs.jna)
    implementation(libs.coroutines.core)
    implementation(libs.kotlinx.datetime)
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.test)
    testImplementation(libs.assertj.core)
}

val buildType = if (System.getenv("RELEASE") == "1") "release" else "debug"

// This is the base directory under `build` that holds all libraries, organized by
// the build type (debug or release) and the target (linux-x86-64 etc.).
val ffiLibsBase = layout.buildDirectory.dir("ffiLibs").get().asFile

val copyFfiLibrary by tasks.registering {
    doLast {
        val libs = listOf(
            Triple("x86_64-unknown-linux-gnu", "linux-x86-64", "so"),
            Triple("aarch64-apple-darwin", "darwin-aarch64", "dylib")
        )
        libs.forEach { (rustTarget, jvmTarget, ext) ->
            val libName = "libcore_crypto_ffi.$ext"
            val src = projectDir.resolve("../../../target/$rustTarget/$buildType/$libName")
            val dest = ffiLibsBase.resolve("$buildType/$jvmTarget/$libName")
            // We try to copy all libraries. If a library does not exist and
            // we're not on CI, just skip it (presumably it does not exist because
            // we're on a different platform). However, if we're on CI, always try
            // to copy the library, which will fail if it does not exist, indicating
            // a bug in the CI setup.
            if (src.exists() || System.getenv("CI") != null) {
                src.copyTo(dest, overwrite = true)
            }
        }
    }
}

tasks.named("compileKotlin") {
    dependsOn(copyFfiLibrary)
}

sourceSets {
    main {
        kotlin {
            srcDir(sharedSources.resolve("kotlin"))
            srcDir(projectDir.resolve("src/main/uniffi"))
        }
        resources {
            srcDirs(ffiLibsBase.resolve(buildType))
        }
    }
    test {
        kotlin {
            srcDir(sharedTestSources.resolve("kotlin"))
        }
    }
}

val jmhIncludes: String? = project.findProperty("jmhIncludes") as? String
val jmhBenchmarkMessageCounts: String? = project.findProperty("jmhBenchmarkMessageCounts") as? String
val jmhBenchmarkMessageSizes: String? = project.findProperty("jmhBenchmarkMessageSizes") as? String
val jmhBenchmarkUserCounts: String? = project.findProperty("jmhBenchmarkUserCounts") as? String
val jmhBenchmarkCipherSuites: String? = project.findProperty("jmhBenchmarkCipherSuites") as? String

fun parseJmhParameterValues(raw: String): List<String> =
    raw.split(",").map(String::trim).filter(String::isNotEmpty)

fun listPropertyOf(vararg values: String) =
    objects.listProperty(String::class.java).apply {
        set(values.toList())
    }

fun listPropertyOf(values: List<String>) =
    objects.listProperty(String::class.java).apply {
        set(values)
    }

jmh {
    fork.set(1)
    resultFormat.set("JSON")
    resultsFile.set(layout.buildDirectory.file("reports/jmh/results.json").get().asFile)
    jmhIncludes?.let {
        includes.set(listOf(it))
    }
    jmhBenchmarkMessageCounts?.let {
        benchmarkParameters.put("messageCount", listPropertyOf(parseJmhParameterValues(it)))
    }
    jmhBenchmarkMessageSizes?.let {
        benchmarkParameters.put("messageSize", listPropertyOf(parseJmhParameterValues(it)))
    }
    jmhBenchmarkUserCounts?.let {
        benchmarkParameters.put("userCount", listPropertyOf(parseJmhParameterValues(it)))
    }
    jmhBenchmarkCipherSuites?.let {
        benchmarkParameters.put("cipherSuite", listPropertyOf(parseJmhParameterValues(it)))
    }

    if (project.hasProperty("profile")) {
        // Set this to the async-profiler .dylib/.so file
        val lib = System.getenv("ASYNC_PROFILER_LIB")
        if (lib == null) error("ASYNC_PROFILER_LIB not set")

        profilers.set(
            listOf(
                "async:output=flamegraph;event=cpu;dir=build/reports/async;libPath=$lib"
            )
        )
    }
}

tasks.named("jmh") {
    outputs.upToDateWhen { false }
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
    source.setFrom(files("src/jmh/kotlin"))
    buildUponDefaultConfig = true
    config.setFrom(files("../detekt.yml"))
}

val sourcesJar = tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}

val dokkaHtmlJar = tasks.register<Jar>("dokkaHtmlJar") {
    dependsOn(tasks.named("dokkaGeneratePublicationHtml"))
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaGeneratePublicationHtml"))
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            artifactId = findProperty("POM_ARTIFACT_ID") as String
            groupId = findProperty("GROUP") as String
            version = findProperty("VERSION_NAME") as String
            artifact(sourcesJar)
            artifact(dokkaHtmlJar)
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
