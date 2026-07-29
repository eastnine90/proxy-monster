package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Wire tokens are always expiring and bounded (DESIGN.md — no persistent secrets). Guards the
 * TTL clamp so a regression can't reintroduce an unbounded (or zero/negative) token lifetime.
 */
class TokenTtlTest {
    @Test fun `requests within the window are unchanged`() {
        assertEquals(900L, clampTtlSeconds(900L))
        assertEquals(3600L, clampTtlSeconds(DEFAULT_USER_TTL_SECONDS))
        assertEquals(SESSION_TTL_SECONDS, clampTtlSeconds(SESSION_TTL_SECONDS))
    }

    @Test fun `over-long requests are capped at 24h`() {
        assertEquals(TOKEN_MAX_TTL_SECONDS, clampTtlSeconds(999_999L))
        assertEquals(TOKEN_MAX_TTL_SECONDS, clampTtlSeconds(Long.MAX_VALUE))
    }

    @Test fun `tiny, zero, and negative requests are floored to the minimum`() {
        assertEquals(TOKEN_MIN_TTL_SECONDS, clampTtlSeconds(1L))
        assertEquals(TOKEN_MIN_TTL_SECONDS, clampTtlSeconds(0L))
        assertEquals(TOKEN_MIN_TTL_SECONDS, clampTtlSeconds(-100L))
    }

    @Test fun `every clamped ttl is a bounded, positive lifetime`() {
        for (req in listOf(-1L, 0L, 30L, 60L, 3600L, 86_400L, 86_401L, Long.MAX_VALUE)) {
            val ttl = clampTtlSeconds(req)
            assertTrue(ttl in TOKEN_MIN_TTL_SECONDS..TOKEN_MAX_TTL_SECONDS, "ttl $ttl out of bounds for request $req")
        }
    }
}
