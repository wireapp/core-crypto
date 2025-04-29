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
    implementation(libs.coroutines.core)
    implementation(project(":uniffi-jvm"))
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.test)
    testImplementation(libs.assertj.core)
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
