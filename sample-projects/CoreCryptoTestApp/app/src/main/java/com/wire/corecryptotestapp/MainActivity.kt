package com.wire.corecryptotestapp

import android.annotation.SuppressLint
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.wire.core.CiphersuiteName
import com.wire.core.ConversationConfiguration
import java.time.Duration
import android.widget.TextView

class MainActivity : AppCompatActivity() {
    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        findViewById<TextView>(R.id.coreCryptoVersion).text = "CoreCrypto v${com.wire.core.version()}"

//        val clientId = "79755d33-9862-4cab-9f5a-2d74d054b059"
//        val convId = "e657d457-c4cd-47ab-b8f4-5f2da25c20dc"
//        val coreCrypto = com.wire.core.initWithPathAndKey("./test.edb", clientId)
//        var message = coreCrypto.createConversation(convId, ConversationConfiguration(
//            extraMembers = emptyList(),
//            ciphersuite = CiphersuiteName.MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448,
//            admins = emptyList(),
//            keyRotationSpan = Duration.ofDays(1),
//        ))
//
//        var encryptedMessage = coreCrypto.encryptMessage(convId, "Secret Message!".toByteArray().asUByteArray().asList())
    }
}