buildscript {
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.20.1")
        classpath("com.android.tools.build:gradle:7.3.1")
    }
}

plugins {
    kotlin("multiplatform") version "1.8.22"
    id("com.vanniktech.maven.publish") version "0.25.3"
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
