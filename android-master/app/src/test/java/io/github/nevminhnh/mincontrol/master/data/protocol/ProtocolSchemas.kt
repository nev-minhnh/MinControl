package io.github.nevminhnh.mincontrol.master.data.protocol

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.networknt.schema.JsonSchema
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SchemaLocation
import com.networknt.schema.SchemaValidatorsConfig
import com.networknt.schema.SpecVersion
import java.io.File

/** Test helper: loads the protocol schema files, mapping the `$id` base URL to the local folder so cross-file `$ref`s resolve. */
object ProtocolSchemas {
    const val BASE = "https://mincontrol.local/protocol/"

    val dir: File = File(requireNotNull(System.getProperty("mincontrol.protocolDir")) { "mincontrol.protocolDir not set" })
    val mapper = ObjectMapper()

    private val factory: JsonSchemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012) { b ->
        b.schemaMappers { m -> m.mapPrefix(BASE, dir.toURI().toString().trimEnd('/') + "/") }
    }
    private val config = SchemaValidatorsConfig.builder().formatAssertionsEnabled(true).build()

    fun schema(stem: String): JsonSchema = factory.getSchema(SchemaLocation.of("$BASE$stem.schema.json"), config)

    fun validate(stem: String, json: String): Set<*> = schema(stem).validate(mapper.readTree(json))

    fun readTree(file: File): JsonNode = mapper.readTree(file)
}
