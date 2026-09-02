package io.github.mortezajavadian.pq.testing

/**
 * The ACVP three-file loader.
 *
 * A NIST ACVP suite directory holds `prompt.json` (inputs), `expectedResults.json` (the answers)
 * and `internalProjection.json` (intermediate values plus the pass/fail flag for check-type
 * groups). The three are walked in lockstep, group by group and case by case, so no expected value
 * is ever produced by the code under test — the property that makes this a validation suite rather
 * than a self-consistency check.
 *
 * The reference implementation pairs cases by array index after asserting the three arrays have
 * equal length. This does that and also asserts the `tcId`s agree, which additionally catches a
 * mirror whose files were regenerated out of order.
 */
internal class AcvpCase(val tid: Int, val p: Obj, val er: Obj, val ip: Obj) {
    val tcId: Int get() = p.int("tcId")
}

internal class AcvpGroup(val gid: Int, val p: Obj, val er: Obj, val ip: Obj) {
    val cases: List<AcvpCase>
        get() {
            val pt = p.objects("tests")
            val et = er.objects("tests")
            val it = ip.objects("tests")
            Check.eq(pt.size, et.size, "group $gid: prompt/expectedResults test counts")
            Check.eq(pt.size, it.size, "group $gid: prompt/internalProjection test counts")
            return pt.indices.map { i ->
                val case = AcvpCase(i, pt[i], et[i], it[i])
                Check.eq(pt[i].int("tcId"), et[i].int("tcId"), "group $gid case $i: tcId in expectedResults")
                Check.eq(pt[i].int("tcId"), it[i].int("tcId"), "group $gid case $i: tcId in internalProjection")
                case
            }
        }

    /** Group-level metadata lives on the prompt group; `tests` is the only key not metadata. */
    fun meta(key: String): String = p.str(key)

    fun metaOrNull(key: String): String? = p.strOrNull(key)
}

/**
 * Streams one ACVP suite. Groups arrive one at a time and are dropped again, so a multi-hundred-
 * megabyte prompt file costs one group of heap rather than the whole document.
 */
internal fun acvp(name: String, body: (Sequence<AcvpGroup>) -> Unit) {
    Vectors.Groups(Vectors.acvp(name, "prompt")).use { p ->
        Vectors.Groups(Vectors.acvp(name, "expectedResults")).use { er ->
            Vectors.Groups(Vectors.acvp(name, "internalProjection")).use { ip ->
                body(
                    sequence {
                        var gid = 0
                        while (true) {
                            val more = p.iterator.hasNext()
                            Check.eq(er.iterator.hasNext(), more, "$name: expectedResults ended early")
                            Check.eq(ip.iterator.hasNext(), more, "$name: internalProjection ended early")
                            if (!more) return@sequence
                            yield(AcvpGroup(gid, p.iterator.next(), er.iterator.next(), ip.iterator.next()))
                            gid++
                        }
                    }
                )
            }
        }
    }
}

/**
 * Streams one Wycheproof file's groups.
 *
 * Wycheproof puts the group's key material on the group and the messages on the cases, so unlike
 * ACVP there is nothing to join — but the empty-file failure mode is the same, which is why every
 * caller runs its loop under a [Tally].
 */
internal fun wycheproof(name: String, body: (Sequence<Obj>) -> Unit) {
    Vectors.Groups(Vectors.wycheproof(name)).use { g ->
        body(g.iterator.asSequence())
    }
}

/**
 * Walks every case of a Wycheproof file under a [Tally], so an empty or truncated archive fails
 * loudly instead of running zero iterations and reporting success — the failure mode the reference
 * suite's own loader guards against, for the same reason.
 *
 * The group is passed alongside each case because Wycheproof puts key material on the group and
 * messages on the cases: an ML-DSA verify file has one `publicKey` and many signatures under it.
 */
internal fun eachGroupCase(name: String, body: (Obj, Obj, String) -> Unit) {
    val tally = Tally(name)
    wycheproof(name) { groups ->
        for (g in groups) {
            tally.group()
            for (t in g.objects("tests").capped(name)) {
                tally.case()
                val comment = t.strOrNull("comment").orEmpty()
                val at = "$name tcId=${t.int("tcId")}" + if (comment.isEmpty()) "" else " ($comment)"
                body(g, t, at)
            }
        }
    }
    tally.requireNonEmpty()
}

internal fun eachCase(name: String, body: (Obj, String) -> Unit) =
    eachGroupCase(name) { _, t, at -> body(t, at) }

/** Wycheproof's verdict field. `acceptable` means legal but discouraged; treated as valid. */
internal fun Obj.isValid(): Boolean = str("result") != "invalid"

/** Wycheproof marks mode variations with flags rather than separate files. */
internal fun Obj.hasFlag(flag: String): Boolean = strings("flags").contains(flag)

/**
 * An optional ceiling on cases per group, for a fast smoke run: `PQ_MAX_CASES=2 ./gradlew test`.
 * Unset means every case runs. A truncated run says so in its own skip line, because a suite that
 * silently sampled reads as one that covered everything.
 */
internal val maxCasesPerGroup: Int =
    System.getenv("PQ_MAX_CASES")?.toIntOrNull()?.takeIf { it > 0 } ?: Int.MAX_VALUE

internal fun <T> List<T>.capped(label: String): List<T> {
    if (size <= maxCasesPerGroup) return this
    Skips.note("$label: PQ_MAX_CASES capped ${size - maxCasesPerGroup} of $size cases")
    return subList(0, maxCasesPerGroup)
}

/**
 * Runs a vector-backed case, turning absent vectors into a reported skip.
 *
 * Absent vectors must not read as a pass, and on a developer machine that has not run
 * `fetch-vectors.sh` they must not read as a failure either — so the case is skipped, loudly, and
 * the summary carries the count. With `PQ_REQUIRE_VECTORS=1` absence is a hard failure, which is
 * how the suite should run anywhere its result is being trusted.
 */
internal inline fun requiringVectors(body: () -> Unit) {
    try {
        body()
    } catch (e: Vectors.Missing) {
        if (Vectors.required) throw AssertionError("PQ_REQUIRE_VECTORS=1 but ${e.message}")
        skipCase(e.message ?: "vectors missing")
    }
}
