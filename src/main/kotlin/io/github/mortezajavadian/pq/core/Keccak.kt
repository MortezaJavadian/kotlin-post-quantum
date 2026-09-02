package io.github.mortezajavadian.pq.core

/**
 * Keccak-f1600, and the sponge on top of it. Everything in this package hashes through this class.
 *
 * ML-KEM and ML-DSA are almost entirely SHA-3: key generation, encapsulation, the matrix expansion,
 * the noise sampling, the challenge and the commitment hash are all Keccak with different padding
 * and rates. So this file is the one place where a wrong bit would change every key and every
 * signature the app produces, and it is written to be checkable against FIPS-202 line by line
 * rather than to be clever.
 *
 * **State layout.** FIPS-202 defines the state as 25 lanes of 64 bits, absorbed and squeezed
 * little-endian. It is kept here as exactly that — a [LongArray] of 25 — instead of the 50-element
 * 32-bit split a JavaScript implementation is forced into for want of a 64-bit integer. The
 * permutation is identical either way; on the JVM the 64-bit form is both shorter and faster.
 *
 * **Padding.** [suffix] is the domain byte: `0x06` for SHA3-*, `0x1f` for SHAKE. The `0x80` branch
 * in [finish] can only trigger for a suffix that already has its top bit set, which none of the four
 * instances here use; it is kept because it is part of the sponge's contract, not because it runs.
 *
 * **Squeezing is incremental.** [writeInto] resumes from [posOut] and permutes only when the
 * current block is exhausted, so a caller can pull an unbounded stream one rate-sized block at a
 * time. That is what `RejNTTPoly` / `SampleNTT` / `ExpandMask` need, and it is why this class exposes
 * [xofInto] separately from [digest].
 *
 * **Lifecycle.** [digest] wipes the state on its way out and the sponge refuses further use, so the
 * key-derived material a fixed-length hash absorbs does not outlive the call. [update] after a
 * squeeze and any use after [destroy] both throw rather than quietly producing a digest over the
 * wrong data. Streaming callers, which must keep squeezing, wipe explicitly when the stream ends.
 *
 * Not thread-safe and not meant to be: a sponge is a mutable stream, and every user here owns its
 * own instance for the duration of one call.
 */
internal class Keccak(
    /** Rate in bytes: 136 for SHA3-256 and SHAKE256, 168 for SHAKE128, 72 for SHA3-512. */
    val blockLen: Int,
    /** Domain-separation byte, `0x06` (SHA-3) or `0x1f` (SHAKE). */
    private val suffix: Int,
    /** Default digest length for [digest]; ignored by [xofInto], which is length-driven. */
    val outputLen: Int,
    /** SHAKE only. Guards [xofInto] so a fixed-length hash cannot be squeezed by mistake. */
    private val enableXOF: Boolean = false,
) {

    private val state = LongArray(25)

    /** θ/χ scratch, hoisted out of [permute] so permuting a block allocates nothing. */
    private val scratch = LongArray(5)
    private var pos = 0
    private var posOut = 0
    private var finished = false
    private var destroyed = false

    /**
     * The sponge's liveness contract: a destroyed sponge is unusable, and a finished one accepts no
     * more input.
     *
     * Not defensive decoration. Every sponge in this package is seeded with key-derived material, so
     * a silent absorb-after-squeeze would yield a *valid-looking* digest over the wrong data — a
     * fault no length check downstream could catch — and a squeeze from a wiped state would yield a
     * valid-looking digest over zeros.
     */
    private fun checkAlive(checkFinished: Boolean) {
        if (destroyed) throw IllegalStateException("Hash instance has been destroyed")
        if (checkFinished && finished) {
            throw IllegalStateException("Hash#digest() has already been called")
        }
    }

    fun update(data: ByteArray): Keccak = update(data, 0, data.size)

    /**
     * Absorbs `data[from until to]`, XOR-ing into the rate and permuting on every full block.
     *
     * The byte-at-a-time XOR is deliberate: it keeps the absorb correct across calls that do not
     * land on a lane boundary, which is the normal case here (a 32-byte seed followed by two
     * one-byte matrix indices).
     */
    fun update(data: ByteArray, from: Int, to: Int): Keccak {
        checkAlive(checkFinished = true)
        var p = from
        while (p < to) {
            val take = minOf(blockLen - pos, to - p)
            var i = 0
            while (i < take) {
                val lane = pos ushr 3
                val shift = (pos and 7) shl 3
                state[lane] = state[lane] xor ((data[p].toLong() and 0xFFL) shl shift)
                pos++
                p++
                i++
            }
            if (pos == blockLen) permute()
        }
        return this
    }

    /** Absorbs one byte — the nonce in ML-KEM's PRF, which is a single-byte counter. */
    fun updateByte(value: Int): Keccak {
        checkAlive(checkFinished = true)
        val lane = pos ushr 3
        val shift = (pos and 7) shl 3
        state[lane] = state[lane] xor ((value.toLong() and 0xFFL) shl shift)
        pos++
        if (pos == blockLen) permute()
        return this
    }

    private fun finish() {
        if (finished) return
        finished = true
        val lane = pos ushr 3
        state[lane] = state[lane] xor ((suffix.toLong() and 0xFFL) shl ((pos and 7) shl 3))
        if (suffix and 0x80 != 0 && pos == blockLen - 1) permute()
        val last = blockLen - 1
        state[last ushr 3] = state[last ushr 3] xor (0x80L shl ((last and 7) shl 3))
        permute()
    }

    /** Squeezes `out.size` bytes, continuing the stream where the previous call stopped. */
    fun writeInto(out: ByteArray): ByteArray {
        checkAlive(checkFinished = false)
        finish()
        var p = 0
        val len = out.size
        while (p < len) {
            if (posOut >= blockLen) permute()
            val take = minOf(blockLen - posOut, len - p)
            var i = 0
            while (i < take) {
                out[p] = (state[posOut ushr 3] ushr ((posOut and 7) shl 3)).toByte()
                posOut++
                p++
                i++
            }
        }
        return out
    }

    /** As [writeInto], refusing a non-XOF instance. */
    fun xofInto(out: ByteArray): ByteArray {
        if (!enableXOF) throw IllegalStateException("XOF is not possible for this instance")
        return writeInto(out)
    }

    /**
     * The fixed-length digest: squeeze [outputLen] bytes, then wipe.
     *
     * Single-shot by construction. Squeezing and *then* destroying is what makes the fixed-length
     * hashes leak-free by default — every `H`, `G`, `µ`, `ρ′`, `c̃` and PRF output in both schemes goes
     * through here, and the sponge state that produced it is key-derived. A caller that needs a
     * resumable stream wants [xofInto], which does not wipe.
     */
    fun digest(): ByteArray {
        checkAlive(checkFinished = true)
        val out = writeInto(ByteArray(outputLen))
        destroy()
        return out
    }

    /** Zeroes the state and marks the sponge unusable. Idempotent. */
    fun destroy() {
        destroyed = true
        state.fill(0L)
        scratch.fill(0L)
    }

    /** FIPS-202 §3.3: θ, ρ, π, χ, ι, twenty-four times. */
    private fun permute() {
        val s = state
        val b = scratch
        for (round in 0 until 24) {
            // θ
            for (x in 0 until 5) {
                b[x] = s[x] xor s[x + 5] xor s[x + 10] xor s[x + 15] xor s[x + 20]
            }
            for (x in 0 until 5) {
                val t = java.lang.Long.rotateLeft(b[(x + 1) % 5], 1) xor b[(x + 4) % 5]
                var y = 0
                while (y < 25) {
                    s[x + y] = s[x + y] xor t
                    y += 5
                }
            }
            // ρ and π, walking the 24-lane cycle that starts at lane 1.
            var cur = s[1]
            for (t in 0 until 24) {
                val target = PI[t]
                val next = s[target]
                s[target] = java.lang.Long.rotateLeft(cur, ROTL[t])
                cur = next
            }
            // χ: A[x][y] ^= ¬A[x+1][y] & A[x+2][y], one row of five lanes at a time.
            var y = 0
            while (y < 25) {
                for (x in 0 until 5) b[x] = s[y + x]
                for (x in 0 until 5) {
                    s[y + x] = s[y + x] xor (b[(x + 1) % 5].inv() and b[(x + 2) % 5])
                }
                y += 5
            }
            // ι
            s[0] = s[0] xor RC[round]
        }
        b.fill(0L)
        posOut = 0
        pos = 0
    }

    private companion object {

        /**
         * The π lane permutation and the ρ rotation offsets, derived rather than tabulated so they
         * can be read against FIPS-202 §3.2.2–3.2.3 directly: `(x, y) ← (y, 2x + 3y)` and
         * `((t + 1)(t + 2) / 2) mod 64`.
         */
        val PI = IntArray(24)
        val ROTL = IntArray(24)

        /**
         * ι round constants: the low bit-plane of the LFSR `rc(t) = x^t mod (x^8 + x^6 + x^5 + x^4 + 1)`
         * placed at bit positions `2^j - 1`. Computed at class-init for the same reason as [PI].
         */
        val RC = LongArray(24)

        init {
            var x = 1
            var y = 0
            var r = 1
            for (round in 0 until 24) {
                val nx = y
                val ny = (2 * x + 3 * y) % 5
                x = nx
                y = ny
                PI[round] = 5 * y + x
                ROTL[round] = ((round + 1) * (round + 2) / 2) % 64
                var t = 0L
                for (j in 0 until 7) {
                    r = ((r shl 1) xor ((r shr 7) * 0x71)) % 256
                    if (r and 2 != 0) t = t xor (1L shl ((1 shl j) - 1))
                }
                RC[round] = t
            }
        }
    }
}
