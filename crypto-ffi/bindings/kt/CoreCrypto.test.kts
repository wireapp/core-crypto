@file:DependsOn("net.java.dev.jna:jna:5.12.1@aar")
@file:DependsOn("junit:junit:4.13")
@file:Import("core/crypto/CoreCrypto.kt")

org.junit.Assert.assertEquals(com.wire.core.version(), "0.3.0")
