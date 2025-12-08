package com.wire.androidinterop

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class InteropResponse {
    @Serializable
    @SerialName("success")
    public data class Success(val value: String) : InteropResponse()

    @Serializable
    @SerialName("failure")
    public data class Failure(val message: String) : InteropResponse()
}
