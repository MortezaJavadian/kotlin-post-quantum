package io.github.mortezajavadian.pq.lattice

import io.github.mortezajavadian.pq.core.Bytes

/**
 * The map between a polynomial coefficient and its packed bit-field representation.
 *
 * Every key, ciphertext and signature in both schemes is a sequence of polynomials packed at `d`
 * bits per coefficient, where `d` and the per-coefficient transform differ by field: 12 bits raw for
 * an ML-KEM public key, 11 and 5 bits *lossily compressed* for its ciphertext, 3 bits offset by η
 * for an ML-DSA secret, 20 bits signed-centred for its response. Separating "how many bits" from
 * "what the value means" is what lets one packer serve all of them.
 */
internal interface IntCoder {
    /** Coefficient → field value. */
    fun encode(value: Int): Int

    /** Field value → coefficient. */
    fun decode(value: Int): Int
}

/** The identity map, for fields stored verbatim (ML-KEM's 12-bit key, ML-DSA's `t1` and `w1`). */
internal object IdentityCoder : IntCoder {
    override fun encode(value: Int): Int = value
    override fun decode(value: Int): Int = value
}

/**
 * LSB-first bit packing of exactly [n] coefficients at [d] bits each.
 *
 * **Order matters and is not the obvious one.** Coefficients fill each byte from the least
 * significant bit up, and a coefficient that straddles a byte boundary has its *low* bits in the
 * earlier byte. This is FIPS-203/204's `BitsToBytes` and it is the opposite of the big-endian
 * intuition; getting it backwards produces keys of the right length that decode to noise.
 *
 * [bytesLen] is `d * n / 8`, always exact — every `d` used by either scheme divides evenly into the
 * 256-coefficient block.
 *
 * The `and mask` on encode is load-bearing rather than defensive: ML-KEM's compression is defined
 * modulo `2^d` and its top value genuinely wraps to zero, and ML-DSA's signed fields arrive negative
 * and are stored as their two's-complement low bits. Both rely on the truncation.
 */
internal class BitPacker(
    private val d: Int,
    private val coder: IntCoder,
    private val n: Int,
) {
    val bytesLen: Int = d * n / 8
    private val mask: Int = Bytes.mask(d)

    /** Packs [poly] into `dst[offset until offset + bytesLen]`. */
    fun encodeInto(poly: IntArray, dst: ByteArray, offset: Int) {
        var buf = 0
        var bufLen = 0
        var pos = offset
        for (i in 0 until n) {
            buf = buf or ((coder.encode(poly[i]) and mask) shl bufLen)
            bufLen += d
            while (bufLen >= 8) {
                dst[pos++] = buf.toByte()
                bufLen -= 8
                buf = buf ushr 8
            }
        }
    }

    fun encode(poly: IntArray): ByteArray =
        ByteArray(bytesLen).also { encodeInto(poly, it, 0) }

    /** Unpacks the [bytesLen] bytes at `src[offset]` into a fresh polynomial. */
    fun decode(src: ByteArray, offset: Int): IntArray {
        val r = IntArray(n)
        var buf = 0
        var bufLen = 0
        var pos = 0
        for (i in 0 until bytesLen) {
            buf = buf or ((src[offset + i].toInt() and 0xFF) shl bufLen)
            bufLen += 8
            while (bufLen >= d) {
                r[pos++] = coder.decode(buf and mask)
                bufLen -= d
                buf = buf ushr d
            }
        }
        return r
    }

    /** Packs a vector of [count] polynomials back to back. */
    fun encodeVecInto(polys: Array<IntArray>, dst: ByteArray, offset: Int, count: Int) {
        var pos = offset
        for (i in 0 until count) {
            encodeInto(polys[i], dst, pos)
            pos += bytesLen
        }
    }

    /** Unpacks [count] consecutive polynomials. */
    fun decodeVec(src: ByteArray, offset: Int, count: Int): Array<IntArray> =
        Array(count) { decode(src, offset + it * bytesLen) }
}
