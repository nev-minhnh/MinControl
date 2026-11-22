package io.github.nevminhnh.mincontrol.master.data.protocol

import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.io.File

/**
 * Contract test: every fixture under `protocol/fixtures/<stem>/{valid,invalid,semantic-invalid}`
 * is validated against `protocol/<stem>.schema.json`. valid -> passes, invalid -> fails,
 * semantic-invalid -> passes the schema (rejected later by the policy validator, not by the schema).
 */
@RunWith(Parameterized::class)
class ProtocolContractTest(
    private val name: String,
    private val stem: String,
    private val file: File,
    private val expectValid: Boolean,
) {
    @Test
    fun fixtureMatchesExpectation() {
        val errors = ProtocolSchemas.schema(stem).validate(ProtocolSchemas.readTree(file))
        if (expectValid) assertTrue("$name should be valid but: $errors", errors.isEmpty())
        else assertTrue("$name should be invalid", errors.isNotEmpty())
    }

    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun fixtures(): List<Array<Any>> {
            val root = File(ProtocolSchemas.dir, "fixtures")
            val out = mutableListOf<Array<Any>>()
            for (stemDir in root.listFiles { f -> f.isDirectory }.orEmpty().sortedBy { it.name }) {
                for ((sub, valid) in listOf("valid" to true, "invalid" to false, "semantic-invalid" to true)) {
                    File(stemDir, sub).listFiles { f -> f.extension == "json" }.orEmpty().sortedBy { it.name }.forEach {
                        out += arrayOf<Any>("${stemDir.name}/$sub/${it.name}", stemDir.name, it, valid)
                    }
                }
            }
            check(out.isNotEmpty()) { "no fixtures found under $root" }
            return out
        }
    }
}
