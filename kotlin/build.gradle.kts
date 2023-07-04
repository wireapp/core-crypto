import java.util.*

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
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
}

val coreCryptoGroupId: String by project
val coreCryptoVersion: String by project

group = coreCryptoGroupId
version = coreCryptoVersion

nexusPublishing {
    repositories {
        sonatype {
            val sonatypeUser: String? = project.getLocalProperty("sonatypeUser")
            val sonatypePassword: String? = project.getLocalProperty("sonatypePassword")
            username.set(sonatypeUser)
            password.set(sonatypePassword)
        }
    }
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

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

fun <T> Project.getLocalProperty(propertyName: String): T? {
    return getLocalProperty(propertyName, this)
}

/**
 * Util to obtain property declared on `$projectRoot/local.properties` file or default
 */
@Suppress("UNCHECKED_CAST")
fun <T> getLocalProperty(propertyName: String, project: Project): T? {
    val localProperties = Properties().apply {
        val localPropertiesFile = project.rootProject.file("local.properties")
        if (localPropertiesFile.exists()) {
            load(localPropertiesFile.inputStream())
        }
    }

    return localProperties.get(propertyName) as? T
}
