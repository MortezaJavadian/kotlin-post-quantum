package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.core.Keccak
import io.github.mortezajavadian.pq.testing.AcvpGroup
import io.github.mortezajavadian.pq.testing.Check
import io.github.mortezajavadian.pq.testing.Skips
import io.github.mortezajavadian.pq.testing.Suite
import io.github.mortezajavadian.pq.testing.Tally
import io.github.mortezajavadian.pq.testing.Vectors
import io.github.mortezajavadian.pq.testing.acvp
import io.github.mortezajavadian.pq.testing.capped
import io.github.mortezajavadian.pq.testing.hex
import io.github.mortezajavadian.pq.testing.int
import io.github.mortezajavadian.pq.testing.objects
import io.github.mortezajavadian.pq.testing.requiringVectors
import io.github.mortezajavadian.pq.testing.str
import io.github.mortezajavadian.pq.testing.suite

/**
 * FIPS 202 against NIST's ACVP vectors — the coverage the reference implementation does not have.
 *
 * `noble-post-quantum` imports its Keccak from `@noble/hashes` and tests it there. This library
 * contains its own, and it is the single most load-bearing file in the package: ML-KEM and ML-DSA are
 * almost entirely SHA-3, so one wrong bit in the permutation changes every key and every signature
 * while every internal round-trip still agrees with itself. That failure is invisible without
 * external vectors, which is why these four SHA3 and four SHAKE suites are here.
 *
 * SHA3-224 and SHA3-384 are not used by either scheme. They are tested anyway because they drive the
 * same permutation at two rates (144 and 104 bytes) that the schemes never exercise, so a padding or
 * rate-boundary error that 136 and 72 happen to hide shows up here.
 *
 * Three ACVP test types are covered and two things are passed over, each counted:
 *
 *  - **AFT** — one message, one digest. NIST generates most of these at bit lengths that are not
 *    multiples of eight; a byte-oriented sponge cannot express them, so those cases are skipped and
 *    counted. What remains is still every rate boundary, the empty message and multi-block inputs.
 *  - **MCT** — 100 × 1000 chained hashes. This is the strongest single check in the suite: an error
 *    anywhere in θ/ρ/π/χ/ι, in the round constants or in the padding diverges within a few
 *    iterations and cannot be recovered from, and the chain's final value depends on all 100,000
 *    invocations.
 *  - **VOT** — SHAKE at a caller-chosen output length, which is what `ExpandA` and `ExpandMask` do.
 *  - **LDT** is skipped: the four cases hash 1, 2, 4 and 8 GiB of repeating content.
 */
internal val acvpSha3Suite: Suite = suite("ACVP FIPS 202") {
    for (h in hashSuites()) {
        test(h.dir) {
            requiringVectors {
                val header = Vectors.header(Vectors.acvp(h.dir, "prompt"))
                Check.eq(header.str("algorithm"), h.algorithm, "${h.dir} algorithm")
                val tally = Tally(h.dir)
                acvp(h.dir) { groups ->
                    for (g in groups) {
                        val type = g.meta("testType")
                        if (type == "LDT") {
                            Skips.note("${h.dir}: LDT hashes 1–8 GiB of repeating content")
                            continue
                        }
                        tally.group()
                        when (type) {
                            "AFT", "VOT" -> h.oneShotGroup(g, tally)
                            "MCT" -> h.monteCarloGroup(g, tally)
                            else -> {
                                Skips.note("${h.dir}: unhandled testType '$type'")
                                tally.case()
                            }
                        }
                    }
                }
                tally.requireNonEmpty()
            }
        }
    }
}

/** One FIPS 202 function, parameterised exactly as the standard's Table 3 gives it. */
private class HashSuite(
    val dir: String,
    val algorithm: String,
    /** Rate in bytes: 200 − 2·(security strength in bytes). */
    val blockLen: Int,
    /** Digest length for a SHA3-*; ignored for a SHAKE, whose length comes from the vector. */
    val digestLen: Int,
    val isXof: Boolean,
) {
    private val suffix: Int get() = if (isXof) 0x1f else 0x06

    fun hash(msg: ByteArray, outLen: Int): ByteArray =
        Keccak(blockLen = blockLen, suffix = suffix, outputLen = outLen, enableXOF = isXof)
            .update(msg)
            .digest()

    /**
     * AFT and VOT differ only in where the output length comes from, so they share a body: AFT fixes
     * it (per function for SHA3, per case for SHAKE) and VOT varies it per case.
     */
    fun oneShotGroup(g: AcvpGroup, tally: Tally) {
        for (t in g.cases.capped(dir)) {
            tally.case()
            val at = "$dir tcId=${t.tcId}"
            val msgBits = t.p.int("len")
            val outBits = if (isXof) t.p.int("outLen") else digestLen * 8
            if (msgBits % 8 != 0) {
                Skips.note("$dir: message length is not a whole number of bytes")
                continue
            }
            if (outBits % 8 != 0) {
                Skips.note("$dir: output length is not a whole number of bytes")
                continue
            }
            val msg = t.p.hex("msg")
            Check.eq(msg.size, msgBits / 8, "$at declared len vs msg bytes")
            Check.eq(hash(msg, outBits / 8), t.er.hex("md"), "$at md")
        }
    }

    /**
     * The two Monte Carlo chains of ACVP's SHA-3 spec, which are not the same algorithm.
     *
     * SHA3 feeds each digest back in whole. SHAKE feeds back only the leading 128 bits and derives
     * the *next* output length from the trailing 16 bits of the digest it just produced, so an
     * implementation that squeezed one byte too many diverges immediately and permanently — the
     * output length is data-dependent.
     */
    fun monteCarloGroup(g: AcvpGroup, tally: Tally) {
        val version = g.metaOrNull("mctVersion") ?: "standard"
        if (version != "standard") {
            Skips.note("$dir: unhandled mctVersion '$version'")
            tally.case()
            return
        }
        for (t in g.cases) {
            tally.case()
            val at = "$dir MCT tcId=${t.tcId}"
            val expected = t.er.objects("resultsArray")
            var seed = t.p.hex("msg")
            if (!isXof) {
                for ((j, want) in expected.withIndex()) {
                    var md = seed
                    for (i in 0 until 1000) md = hash(md, digestLen)
                    Check.eq(md, want.hex("md"), "$at iteration $j")
                    seed = md
                }
                continue
            }
            // OutputLen and Range are byte counts; the group states them in bits.
            val minBytes = g.p.int("minOutLen") / 8
            val range = g.p.int("maxOutLen") / 8 - minBytes + 1
            var outLen = g.p.int("maxOutLen") / 8
            for ((j, want) in expected.withIndex()) {
                var md = seed
                for (i in 0 until 1000) {
                    val msg = md.copyOf(16)
                    md = hash(msg, outLen)
                    val rightmost = ((md[md.size - 2].toInt() and 0xff) shl 8) or (md[md.size - 1].toInt() and 0xff)
                    outLen = minBytes + rightmost % range
                }
                Check.eq(md, want.hex("md"), "$at iteration $j")
                Check.eq(md.size * 8, want.int("outLen"), "$at iteration $j outLen")
                seed = md
            }
        }
    }
}

/**
 * The eight suite directories the fetch script pulls, and the FIPS 202 parameters each one names.
 *
 * A function rather than a top-level `val`, because the suite builder above runs during this file's
 * own class initialisation: a property declared below it would still be null at that point.
 *
 * The `1.0` and `FIPS202` SHAKE revisions are both listed because they are different files with
 * different case mixes, not two names for one: `1.0` carries the Monte Carlo and variable-output
 * groups, `FIPS202` carries byte-aligned messages the older revision mostly does not.
 */
private fun hashSuites(): List<HashSuite> = listOf(
    HashSuite("SHA3-224-2.0", "SHA3-224", blockLen = 144, digestLen = 28, isXof = false),
    HashSuite("SHA3-256-2.0", "SHA3-256", blockLen = 136, digestLen = 32, isXof = false),
    HashSuite("SHA3-384-2.0", "SHA3-384", blockLen = 104, digestLen = 48, isXof = false),
    HashSuite("SHA3-512-2.0", "SHA3-512", blockLen = 72, digestLen = 64, isXof = false),
    HashSuite("SHAKE-128-1.0", "SHAKE-128", blockLen = 168, digestLen = 0, isXof = true),
    HashSuite("SHAKE-128-FIPS202", "SHAKE-128", blockLen = 168, digestLen = 0, isXof = true),
    HashSuite("SHAKE-256-1.0", "SHAKE-256", blockLen = 136, digestLen = 0, isXof = true),
    HashSuite("SHAKE-256-FIPS202", "SHAKE-256", blockLen = 136, digestLen = 0, isXof = true),
)
