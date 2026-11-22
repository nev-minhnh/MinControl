package io.github.nevminhnh.mincontrol.master.data.protocol

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** Mirrors `protocol/signed-envelope.schema.json`. `payload` = base64url (no padding) of the UTF-8 [SignedBody] JSON. */
@Serializable
data class SignedEnvelope(
    val v: Int = 1,
    val alg: SigAlg,
    val keyId: String,
    val payload: String,
    val sig: String,
)

@Serializable
enum class SigAlg {
    @SerialName("ed25519") ED25519,
    @SerialName("es256") ES256,
}

@Serializable
enum class BodyKind {
    @SerialName("policy") POLICY,
    @SerialName("command") COMMAND,
}

/**
 * Mirrors `protocol/signed-body.schema.json`. [body] is a policy or a [Command] depending on [kind];
 * kept as a raw [JsonObject] so the exact signed bytes are never re-serialised.
 */
@Serializable
data class SignedBody(
    val deviceId: String,
    val kind: BodyKind,
    val seq: Long,
    val issuedAt: String,
    val expiresAt: String,
    val body: JsonObject,
)
