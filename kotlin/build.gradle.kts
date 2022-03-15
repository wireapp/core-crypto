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
//    id("signing")
    id("maven-publish")
}

//signing {
//    val signingKey: String? by project
//    val signingPassword: String? by project
//    useInMemoryPgpKeys(signingKey, signingPassword)
//    sign(publishing.publications)
//}

publishing {
    repositories {
        maven {
            url = uri("../local-maven/")
        }
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

