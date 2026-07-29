package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Pure unit tests for [ScimPatchValidator] — no DB, no HTTP. Proves the CORE SUBSET
 * (docs/auth-model.md "PATCH: only the core provisioning subset") is exactly two shapes:
 * {op:replace, path:active, value:<bool>} and {op:add|remove, path:members, value:[{value}, ...]}.
 * Everything else — other paths, wrong ops, filter-path grammar, malformed values, multi-op
 * requests — is rejected with `invalidPath`/`invalidValue`, never silently accepted.
 */
class ScimPatchValidatorTest {
    @Test fun `accepts replace active true`() {
        val action = ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "replace", path = "active", value = JsonPrimitive(true))))
        assertEquals(ScimPatchAction.SetActive(true), action)
    }

    @Test fun `accepts replace active false`() {
        val action = ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "replace", path = "active", value = JsonPrimitive(false))))
        assertEquals(ScimPatchAction.SetActive(false), action)
    }

    @Test fun `op is case-insensitive for replace active`() {
        val action = ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "REPLACE", path = "active", value = JsonPrimitive(true))))
        assertEquals(ScimPatchAction.SetActive(true), action)
    }

    @Test fun `accepts add members with a value array`() {
        val value = buildJsonArray {
            add(buildJsonObject { put("value", JsonPrimitive("1")) })
            add(buildJsonObject { put("value", JsonPrimitive("2")) })
        }
        val action = ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "add", path = "members", value = value)))
        assertEquals(ScimPatchAction.MemberOp("add", listOf("1", "2")), action)
    }

    @Test fun `accepts remove members with a value array`() {
        val value = buildJsonArray { add(buildJsonObject { put("value", JsonPrimitive("3")) }) }
        val action = ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "remove", path = "members", value = value)))
        assertEquals(ScimPatchAction.MemberOp("remove", listOf("3")), action)
    }

    @Test fun `rejects an unsupported path`() {
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "replace", path = "userName", value = JsonPrimitive("nope"))))
        }
        assertEquals("invalidPath", ex.scimType)
    }

    @Test fun `rejects a non-boolean active value`() {
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "replace", path = "active", value = JsonPrimitive("yes"))))
        }
        assertEquals("invalidValue", ex.scimType)
    }

    @Test fun `rejects filter-path grammar on members`() {
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(
                listOf(ScimPatchOperation(op = "remove", path = "members[value eq \"2\"]", value = null)),
            )
        }
        assertEquals("invalidPath", ex.scimType)
    }

    @Test fun `rejects replace on members (wrong op for that path)`() {
        val value = buildJsonArray { add(buildJsonObject { put("value", JsonPrimitive("1")) }) }
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "replace", path = "members", value = value)))
        }
        assertEquals("invalidPath", ex.scimType)
    }

    @Test fun `rejects add on active (wrong op for that path)`() {
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "add", path = "active", value = JsonPrimitive(true))))
        }
        assertEquals("invalidPath", ex.scimType)
    }

    @Test fun `rejects a members value that is not an array of objects`() {
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "add", path = "members", value = JsonPrimitive("1"))))
        }
        assertEquals("invalidValue", ex.scimType)
    }

    @Test fun `rejects multiple operations`() {
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(
                listOf(
                    ScimPatchOperation(op = "replace", path = "active", value = JsonPrimitive(true)),
                    ScimPatchOperation(op = "replace", path = "active", value = JsonPrimitive(false)),
                ),
            )
        }
        assertEquals("invalidPath", ex.scimType)
    }

    @Test fun `rejects an empty Operations list`() {
        val ex = assertFailsWith<ScimPatchInvalidException> { ScimPatchValidator.validate(emptyList()) }
        assertEquals("invalidPath", ex.scimType)
    }

    @Test fun `rejects a missing path`() {
        val ex = assertFailsWith<ScimPatchInvalidException> {
            ScimPatchValidator.validate(listOf(ScimPatchOperation(op = "replace", path = null, value = JsonPrimitive(true))))
        }
        assertTrue(ex.scimType == "invalidPath")
    }
}
