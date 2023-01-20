plugins {
    id("com.android.library")
    id("kotlin-android")
    id("maven-publish")
}

android {
    compileSdk = 31

    defaultConfig {
        minSdk = 21
        targetSdk = 31
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(file("proguard-android-optimize.txt"), file("proguard-rules.pro"))
        }
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.8.0@aar")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk7")
    implementation("androidx.appcompat:appcompat:1.4.0")
    implementation("androidx.core:core-ktx:1.7.0")
    api("org.slf4j:slf4j-api:1.7.30")

    androidTestImplementation("com.github.tony19:logback-android:2.0.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.3")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.4.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.4.1")
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

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("maven") {
                groupId = "com.wire"
                artifactId = "core-crypto-android"
                version = "0.6.0-rc.4"
                from(components["release"])
                pom {
                    name.set("core-crypto-android")
                    description.set(
                            "MLS/Proteus multiplexer abstraction with encrypted persistent storage in Rust."
                    )
                    url.set("https://github.com/wireapp/core-crypto")
                    licenses {
                        license {
                            name.set("GPL-3.0")
                            url.set("https://github.com/wireapp/core-crypto/blob/main/LICENSE")
                        }
                    }
                    scm {
                        connection.set("scm:git:github.com/wireapp/core-crypto.git")
                        developerConnection.set("scm:git:ssh://github.com/wireapp/core-crypto.git")
                        url.set("https://github.com/wireapp/core-crypto")
                    }
                }
            }
        }
    }
}
