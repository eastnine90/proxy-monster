package com.ridi.oss.proxymonster.probe

import com.ridi.oss.proxymonster.grpc.ColumnMask

/** Result of binding: masks keyed by result-set index, plus any masks that could not bind. */
data class MaskBinding(val byIndex: Map<Int, String>, val unbound: List<ColumnMask>) {
    val allBound: Boolean get() = unbound.isEmpty()
}

/**
 * Bind mask specs to result-set column indexes BY OUTPUT POSITION (the ordinal the analyzer assigned),
 * shared by the control plane and both wire proxies. Position is immune to alias/case/EXPR$0 name
 * mismatch — name binding was the fail-open bug. Any mask whose ordinal is out of range of the live
 * result set is reported as unbound so callers can fail closed ("every required mask must bind, else DENY").
 * An ABSENT ordinal (proto explicit-presence: `hasOrdinal()` false) never binds — it is reported unbound so
 * a malformed/omitted mask fails closed rather than silently binding to result column 0.
 */
fun bindMasks(masks: List<ColumnMask>, resultColumnCount: Int): MaskBinding {
    val byIndex = LinkedHashMap<Int, String>()
    val unbound = ArrayList<ColumnMask>()
    for (m in masks) {
        if (m.hasOrdinal() && m.ordinal in 0 until resultColumnCount) byIndex.putIfAbsent(m.ordinal, m.kind)
        else unbound += m
    }
    return MaskBinding(byIndex, unbound)
}
