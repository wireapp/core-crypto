plugins {
    kotlin("multiplatform") version "1.6.10"
}

repositories {
    mavenCentral()
}

kotlin {
    android {
        publishLibraryVariants("release", "debug")
    }
    binaries {
        sharedLib {
            baseName = "native"
        }
    }
}

tasks.withType<Wrapper> {
    gradleVersion = "6.7.1"
    distributionType = Wrapper.DistributionType.LIB
}

android.libraryVariants.all { variant ->
    def sourceSet = variant.sourceSets.find { it.name == variant.name }
    sourceSet.java.srcDir new File(buildDir, "generated/source/uniffi/${variant.name}/java")
    // XXX: I've been trying to make this work but I can't, so the compiled bindings will show as "regular sources" in Android Studio.
    idea.module.generatedSourceDirs += file("${buildDir}/generated/source/uniffi/${variant.name}/java/uniffi")
}

dependencies {
    implementation "net.java.dev.jna:jna:5.7.0@aar"
}
