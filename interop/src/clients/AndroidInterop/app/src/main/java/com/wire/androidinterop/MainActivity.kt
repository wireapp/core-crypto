package com.wire.androidinterop

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.wire.androidinterop.ui.theme.AndroidInteropTheme
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json

class MainActivity : ComponentActivity() {

    val actionHandler = runBlocking {
        InteropActionHandler(InteropActionHandler.defaultCoreCryptoClient())
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AndroidInteropTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    InteropLabel(
                        modifier =  Modifier.padding(innerPadding)
                    )
                }
            }
        }
        println("Ready")
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)

        if (intent == null || intent.action?.compareTo(Intent.ACTION_RUN) != 0) {
            return
        }

        try {
            val action = InteropAction.fromIntent(intent)
            runBlocking {
                actionHandler.handleAction(action)
                    .onSuccess { println(Json.encodeToString(InteropResponse.serializer(), InteropResponse.Success(it))) }
                    .onFailure { println(Json.encodeToString(InteropResponse.serializer(),InteropResponse.Failure(it.message ?: "Unknown error"))) }
            }
        } catch (e: Throwable) {
            return println(Json.encodeToString(InteropResponse.serializer(), InteropResponse.Failure(e.message ?: "Unknown error")))
        }
    }

}

@Preview(showBackground = true)
@Composable
fun InteropLabel(modifier: Modifier) {
    AndroidInteropTheme {
        Text(
            text = "Android Interop",
            modifier = modifier
        )
    }
}
