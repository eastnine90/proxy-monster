package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [parseRequesterIp] extracts the bare IP from a proxy-supplied client_addr (Netty
 * SocketAddress.toString()) for the Cedar `requester_ip`. Fail-closed — anything unparseable → null (the
 * attribute is then absent, never malformed).
 */
class RequesterIpParseTest {
    @Test
    fun `extracts the ip from Netty host-port forms`() {
        assertEquals("1.2.3.4", parseRequesterIp("/1.2.3.4:5432"))
        assertEquals("::1", parseRequesterIp("/[::1]:5432"))
        assertEquals("2001:db8::1", parseRequesterIp("/[2001:db8::1]:443"))
        assertEquals("10.0.0.1", parseRequesterIp("10.0.0.1:5432"))
        assertEquals("192.168.1.1", parseRequesterIp("192.168.1.1"))
        assertEquals("100.100.5.5", parseRequesterIp("/100.100.5.5:0"))
    }

    @Test
    fun `null blank empty or slash-only yield null — fail closed`() {
        assertEquals(null, parseRequesterIp(null))
        assertEquals(null, parseRequesterIp(""))
        assertEquals(null, parseRequesterIp("   "))
        assertEquals(null, parseRequesterIp("/"))
    }
}
