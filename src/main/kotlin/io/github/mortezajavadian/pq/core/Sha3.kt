package io.github.mortezajavadian.pq.core

/**
 * The four SHA-3 instances the post-quantum schemes use, and the seeded XOF wrapper they expand
 * matrices with.
 *
 * Parameterisation is FIPS-202's, restated here only because these exact four are the whole surface:
 *
 * | function  | rate | suffix | output |
 * |-----------|------|--------|--------|
 * | SHA3-256  | 136  | 0x06   | 32     |
 * | SHA3-512  |  72  | 0x06   | 64     |
 * | SHAKE-128 | 168  | 0x1f   | any    |
 * | SHAKE-256 | 136  | 0x1f   | any    |
 *
 * SHA3-256/512 are ML-KEM's `H` and `G`. SHAKE-256 is its KDF and PRF, and is ML-DSA's everything —
 * message representative, private seed, challenge, commitment. SHAKE-128 expands the public matrix
 * `A` in both schemes.
 *
 * These four factories are also the only way to build a [Keccak], whose constructor is internal:
 * every one of them pairs a rate with the suffix FIPS-202 pairs it with, which is a property no
 * runtime check can restore once a caller is free to choose the two independently.
 */
public object Sha3 {

    public fun sha3_256(): Keccak = Keccak(blockLen = 136, suffix = 0x06, outputLen = 32)

    public fun sha3_512(): Keccak = Keccak(blockLen = 72, suffix = 0x06, outputLen = 64)

    public fun shake128(dkLen: Int): Keccak =
        Keccak(blockLen = 168, suffix = 0x1f, outputLen = dkLen, enableXOF = true)

    public fun shake256(dkLen: Int): Keccak =
        Keccak(blockLen = 136, suffix = 0x1f, outputLen = dkLen, enableXOF = true)

    /** `sha3_256(data)`. */
    public fun hash256(data: ByteArray): ByteArray = sha3_256().update(data).digest()

    /**
     * `sha3_512(a || b)`, the two-part form both ML-KEM `G` calls use.
     *
     * Internal: at a public boundary a two-argument hash reads like a keyed one, and it is not —
     * `hash512(k, m)` is length-extendable and unsuitable as a MAC. Concatenate explicitly, or use
     * [hash512] of one array.
     */
    internal fun hash512(a: ByteArray, b: ByteArray): ByteArray =
        sha3_512().update(a).update(b).digest()

    public fun hash512(data: ByteArray): ByteArray = sha3_512().update(data).digest()

    /** `shake256(data, dkLen)`. */
    public fun shake256Of(data: ByteArray, dkLen: Int): ByteArray =
        shake256(dkLen).update(data).digest()

    /**
     * ML-KEM's PRF: `SHAKE256(key || nonce, dkLen)` with `nonce` a single byte.
     *
     * The nonce is appended as one byte and not as a one-element array, which is the same absorb —
     * the sponge takes bytes, not messages — and saves an allocation per noise polynomial. ML-KEM-1024
     * calls this nine times per encrypt.
     *
     * Internal: it is FIPS 203's `PRF`, whose one-byte counter is only meaningful inside ML-KEM's
     * noise sampling, and nothing about the name says the second argument may not exceed 255.
     */
    internal fun prf(dkLen: Int, key: ByteArray, nonce: Int): ByteArray =
        shake256(dkLen).update(key).updateByte(nonce).digest()

    /**
     * A seeded, indexable XOF stream — `ExpandA` in both schemes and `ExpandMask` in ML-DSA.
     *
     * The shape is dictated by how the callers consume it. `A[i][j]` is sampled by rejection, so the
     * consumer needs an *unbounded* stream per `(i, j)` pair, and it needs a new stream for the next
     * pair without re-hashing the seed prefix by hand. So: [seek] fixes the two index bytes and
     * restarts the sponge, and [next] squeezes one more block from wherever the stream is.
     *
     * [next] returns the **same** buffer every time, refilled. The rejection samplers read a block
     * fully before asking for another, so a fresh array per block would be pure garbage — and
     * ML-DSA-87 key generation alone pulls 71 of them.
     *
     * `blockLen` defaults to the sponge's rate, which matters for more than efficiency: the two
     * 12-bit and 24-bit rejection samplers require a block length divisible by 3, which 168 and 136
     * are. ML-DSA's mask expansion overrides it to `ZCoder.bytesLen` because there each squeeze is
     * one encoded polynomial, not a stream to be scanned.
     *
     * Build one with [xof128] or [xof256]; the constructor is internal because `use128` is a flag
     * parameter, and `SeededXof(seed, 168, false)` is a SHAKE-256 sponge squeezed in SHAKE-128-sized
     * blocks — a combination neither scheme has a use for.
     */
    public class SeededXof internal constructor(
        seed: ByteArray,
        private val blockLen: Int,
        private val use128: Boolean,
    ) {
        private val seeded = ByteArray(seed.size + 2).also { seed.copyInto(it) }
        private val seedLen = seed.size
        private val buf = ByteArray(blockLen)
        private var sponge: Keccak = newSponge()

        private fun newSponge(): Keccak =
            if (use128) shake128(blockLen) else shake256(blockLen)

        /** Restarts the stream for matrix position `(x, y)`. */
        public fun seek(x: Int, y: Int): SeededXof {
            seeded[seedLen] = x.toByte()
            seeded[seedLen + 1] = y.toByte()
            sponge.destroy()
            sponge = newSponge()
            sponge.update(seeded)
            return this
        }

        /**
         * The next `blockLen` bytes, in a reused buffer.
         *
         * The array is this object's own scratch, not a fresh one: two successive calls return the
         * *same* reference with different contents, and [clean] zeroes it. Read a block before asking
         * for the next, and copy it if you need to keep it — `val a = next(); val b = next()` leaves
         * `a === b`, so treating them as two independent blocks of randomness silently uses one twice.
         */
        public fun next(): ByteArray = sponge.xofInto(buf)

        /** Wipes the sponge state, the squeezed block and the seed. The stream is unusable after. */
        public fun clean() {
            sponge.destroy()
            buf.fill(0)
            seeded.fill(0)
        }
    }

    /** `XOF128(seed)` — SHAKE-128 at its natural 168-byte rate. */
    public fun xof128(seed: ByteArray, blockLen: Int = 168): SeededXof =
        SeededXof(seed, blockLen = blockLen, use128 = true)

    /** `XOF256(seed)` — SHAKE-256 at its natural 136-byte rate unless overridden. */
    public fun xof256(seed: ByteArray, blockLen: Int = 136): SeededXof =
        SeededXof(seed, blockLen = blockLen, use128 = false)
}
