package io.github.nevminhnh.mincontrol.master.data.protocol

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonClassDiscriminator

/**
 * Master -> device command, mirrors `protocol/command.schema.json`.
 * Discriminated by the `"type"` property. Timestamps are RFC 3339 UTC strings.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("type")
sealed interface Command {
    val commandId: String

    @Serializable @SerialName("lock_now")
    data class LockNow(override val commandId: String, val userSid: String, val until: String? = null) : Command

    @Serializable @SerialName("unlock")
    data class Unlock(override val commandId: String, val userSid: String) : Command

    @Serializable @SerialName("add_time")
    data class AddTime(
        override val commandId: String,
        val userSid: String,
        val minutes: Int,
        val group: String? = null,
    ) : Command

    @Serializable @SerialName("pause_limits")
    data class PauseLimits(override val commandId: String, val userSid: String, val until: String) : Command

    @Serializable @SerialName("screenshot")
    data class Screenshot(override val commandId: String, val userSid: String? = null) : Command

    @Serializable @SerialName("message")
    data class Message(override val commandId: String, val userSid: String, val text: String) : Command

    @Serializable @SerialName("approve_exe")
    data class ApproveExe(
        override val commandId: String,
        val userSid: String,
        val sha256: String,
        val decision: Decision,
    ) : Command

    @Serializable @SerialName("kill_process")
    data class KillProcess(
        override val commandId: String,
        val userSid: String,
        val pid: Int,
        val exe: String? = null,
    ) : Command

    @Serializable @SerialName("logoff")
    data class Logoff(override val commandId: String, val userSid: String) : Command

    @Serializable @SerialName("refresh")
    data class Refresh(override val commandId: String) : Command
}

@Serializable
enum class Decision {
    @SerialName("allow") ALLOW,
    @SerialName("block") BLOCK,
}

/** Shared JSON configuration for protocol (de)serialisation: strict on unknown keys, omits nulls. */
@OptIn(ExperimentalSerializationApi::class)
val ProtocolJson: Json = Json {
    ignoreUnknownKeys = false
    explicitNulls = false
    encodeDefaults = false
}
