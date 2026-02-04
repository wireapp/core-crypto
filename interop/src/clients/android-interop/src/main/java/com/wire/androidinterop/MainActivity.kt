package com.wire.androidinterop

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json

class MainActivity : Activity() {
    val actionHandler = runBlocking {
        InteropActionHandler(InteropActionHandler.defaultCoreCryptoClient())
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        println("Ready")
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        if (intent.action?.compareTo(Intent.ACTION_RUN) != 0) {
            return
        }

        try {
            val action = InteropAction.fromIntent(intent)
            runBlocking {
                actionHandler.handleAction(action)
                    .onSuccess { println(Json.encodeToString(InteropResponse.serializer(), InteropResponse.Success(it))) }
                    .onFailure {
                        println(Json.encodeToString(InteropResponse.serializer(), InteropResponse.Failure(it.message ?: "Unknown error")))
                    }
            }
        } catch (e: Throwable) {
            return println(Json.encodeToString(InteropResponse.serializer(), InteropResponse.Failure(e.message ?: "Unknown error")))
        }
    }
}
