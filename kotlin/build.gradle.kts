buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:7.0.4")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.6.10")
    }
}

plugins {
    id("maven-publish")
}

publishing {
    repositories {
        maven {
            name = "WireMaven"
            url = uri("../../wire-maven/releases")
        }
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

