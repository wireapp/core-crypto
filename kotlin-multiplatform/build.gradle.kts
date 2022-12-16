buildscript {
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.18.5")
        classpath("com.android.tools.build:gradle:7.3.1")
    }
}

plugins {
    kotlin("multiplatform") version "1.7.20"
    id("maven-publish")
}

kotlin {
    jvm() // just a dummy
}

subprojects {
    apply(plugin = "kotlinx-atomicfu")
    apply(plugin = "org.jetbrains.kotlin.multiplatform")
    apply(plugin = "com.android.library")
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
