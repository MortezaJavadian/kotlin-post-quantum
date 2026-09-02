package io.github.mortezajavadian.pq.testing

import java.io.StringReader

/**
 * Tests for the test suite's own JSON reader.
 *
 * Every expected value in this project arrives through [Json]. A reader that mis-decodes one hex
 * string, drops one array element or silently returns an empty group list turns a real mismatch into
 * a green run — the failure this whole suite exists to prevent, reintroduced one layer down. So the
 * parser is tested like production code, and hermetically: these cases parse string literals and need
 * no vector files, so they run even on a machine that has never fetched them.
 */
internal val jsonSelfTestSuite: Suite = suite("JSON reader") {

    test("scalars") {
        Check.eq(read("\"hi\"") as String, "hi", "string")
        Check.eq(read("42") as Long == 42L, true, "integer is Long")
        Check.eq(read("-7") as Long == -7L, true, "negative integer")
        Check.eq(read("0") as Long == 0L, true, "zero")
        Check.eq(read("1.5") as Double == 1.5, true, "fraction is Double")
        Check.eq(read("2e3") as Double == 2000.0, true, "exponent is Double")
        Check.eq(read("true") as Boolean, true, "true")
        Check.eq(read("false") as Boolean, false, "false")
        Check.ok(read("null") == null, "null")
        Check.eq(read("  \n\t 5 ") as Long == 5L, true, "leading whitespace")
    }

    /**
     * `\u` matters and `\/` matters: Wycheproof comments carry both, and a reader that passed `\/`
     * through as two characters would corrupt a case label rather than a value — which is worse,
     * because the run stays green and the label lies.
     */
    test("string escapes") {
        Check.eq(read("\"a\\\"b\"") as String, "a\"b", "escaped quote")
        Check.eq(read("\"a\\\\b\"") as String, "a\\b", "escaped backslash")
        Check.eq(read("\"a\\/b\"") as String, "a/b", "escaped solidus")
        Check.eq(read("\"a\\nb\"") as String, "a\nb", "newline")
        Check.eq(read("\"a\\tb\"") as String, "a\tb", "tab")
        Check.eq(read("\"a\\rb\"") as String, "a\rb", "carriage return")
        Check.eq(read("\"a\\bb\"") as String, "a\bb", "backspace")
        Check.eq(read("\"a\\fb\"") as String, "a\u000Cb", "form feed")
        Check.eq(read("\"\\u0041\\u00e9\\u2713\"") as String, "Aé✓", "unicode escapes")
        Check.eq(read("\"\"") as String, "", "empty string")
    }

    test("objects and arrays") {
        val doc = """{"a":1,"b":[1,2,{"c":"d"}],"e":{},"f":[],"g":[{"h":1},{"h":2}]}"""
        val o = obj(read(doc))
        Check.eq(o.int("a"), 1, "scalar member")
        Check.eq(o.objects("g").size, 2, "objects() length")
        Check.eq(o.objects("g")[1].int("h"), 2, "objects() element")
        // objects() casts every element rather than filtering, so a mixed array must fail loudly:
        // a group list that silently dropped its non-object members would under-count test cases.
        Check.throws("objects() on a mixed array") { o.objects("b") }
        val b = o["b"] as List<*>
        Check.eq(b.size, 3, "array length")
        Check.eq(obj(b[2]).str("c"), "d", "nested object in array")
        Check.eq(obj(o["e"]).isEmpty(), true, "empty object")
        Check.eq((o["f"] as List<*>).isEmpty(), true, "empty array")
        Check.eq(o.objects("f").size, 0, "objects() on an empty array")
    }

    /**
     * The streaming contract. `arrayAt` must yield the array's elements without reading what follows,
     * which is what makes a 700 MB `prompt.json` parse in one group of heap — so the proof is a
     * document whose tail is unparseable: if the reader touched it, this case would throw.
     */
    test("arrayAt streams and stops") {
        val doc = """{"vsId":1,"algorithm":"SHA3-256","testGroups":[{"tgId":1},{"tgId":2}],"tail":@@@}"""
        val groups = Json(StringReader(doc)).arrayAt("testGroups").toList()
        Check.eq(groups.size, 2, "group count")
        Check.eq(obj(groups[0]).int("tgId"), 1, "first group")
        Check.eq(obj(groups[1]).int("tgId"), 2, "second group")
    }

    /**
     * Skipping a value must not be confused by braces and brackets *inside strings*, which is
     * exactly what Wycheproof's `notes` object is full of. A `skipNested` that counted raw characters
     * would end the skip early and then read the rest of the note as if it were the document.
     */
    test("arrayAt skips strings containing structure") {
        val doc = """{"notes":{"a":"} ] { [ \" \\","b":["]","{"]},"testGroups":[{"tgId":9}]}"""
        val groups = Json(StringReader(doc)).arrayAt("testGroups").toList()
        Check.eq(groups.size, 1, "group count past a tricky notes object")
        Check.eq(obj(groups[0]).int("tgId"), 9, "tgId")
    }

    test("arrayAt on an empty array") {
        Check.eq(Json(StringReader("""{"testGroups":[]}""")).arrayAt("testGroups").toList().size, 0, "no groups")
    }

    test("arrayAt fails when the key is absent") {
        Check.throws("missing key") { Json(StringReader("""{"a":1}""")).arrayAt("testGroups").toList() }
        Check.throws("empty document") { Json(StringReader("{}")).arrayAt("testGroups").toList() }
    }

    /** The header read: scalars before the key, nested values skipped, nothing after it. */
    test("scalarsBefore") {
        val doc = """{"vsId":7,"algorithm":"ML-KEM-1024","mode":"keyGen","revision":"FIPS203",""" +
            """"isSample":true,"notes":{"x":1},"list":[1,2],"testGroups":[{"tgId":1}]}"""
        val head = Json(StringReader(doc)).scalarsBefore("testGroups")
        Check.eq(head.int("vsId"), 7, "vsId")
        Check.eq(head.str("algorithm"), "ML-KEM-1024", "algorithm")
        Check.eq(head.str("mode"), "keyGen", "mode")
        Check.eq(head.str("revision"), "FIPS203", "revision")
        Check.eq(head.bool("isSample"), true, "isSample")
        Check.eq(head.containsKey("notes"), false, "nested object skipped")
        Check.eq(head.containsKey("list"), false, "nested array skipped")
        Check.eq(head.containsKey("testGroups"), false, "stops at the key")
        Check.eq(Json(StringReader("{}")).scalarsBefore("testGroups").size, 0, "empty document")
        Check.eq(
            Json(StringReader("""{"a":1}""")).scalarsBefore("testGroups").int("a"),
            1,
            "key absent returns what it read",
        )
    }

    test("malformed input fails loudly") {
        Check.throws("unterminated string") { read("\"abc") }
        Check.throws("unterminated object") { read("""{"a":1""") }
        Check.throws("unterminated array") { read("[1,2") }
        Check.throws("bad literal") { read("tru") }
        Check.throws("missing colon") { read("""{"a" 1}""") }
        Check.throws("missing comma") { read("""{"a":1 "b":2}""") }
        Check.throws("empty input") { read("") }
        Check.throws("bare comma") { read("[,]") }
        Check.throws("bad escape") { read("\"a\\qb\"") }
        Check.throws("bad unicode escape") { read("\"a\\u00zzb\"") }
        Check.throws("non-string key") { read("{1:2}") }
    }

    /**
     * The accessors, which are the last step before a value reaches an assertion. A typo'd field name
     * must fail here rather than resolve to null and compare equal to an absent expectation.
     */
    test("accessors reject the wrong type") {
        val o = obj(read("""{"s":"ab","n":3,"b":true,"z":null,"arr":[{"k":1}]}"""))
        Check.eq(o.str("s"), "ab", "str")
        Check.eq(o.int("n"), 3, "int")
        Check.eq(o.bool("b"), true, "bool")
        Check.eq(o.has("z"), false, "has() is false for an explicit null")
        Check.eq(o.has("s"), true, "has()")
        Check.eq(o.has("nope"), false, "has() for an absent key")
        Check.ok(o.strOrNull("nope") == null, "strOrNull")
        Check.eq(o.boolOr("nope", true), true, "boolOr fallback")
        Check.eq(o.objects("arr")[0].int("k"), 1, "objects")
        Check.throws("str on a number") { o.str("n") }
        Check.throws("int on a string") { o.int("s") }
        Check.throws("bool on a number") { o.bool("n") }
        Check.throws("objects on a scalar") { o.objects("n") }
        Check.throws("absent field") { o.str("nope") }
    }

    /**
     * Hex, which every byte string in every vector file passes through. The one-bit case is the point:
     * a decoder that returned a shorter array, or ignored a nibble, would make mismatching values
     * compare equal.
     */
    test("hex") {
        Check.eq(Hex.decode(""), ByteArray(0), "empty")
        Check.eq(Hex.decode("00ff7f80"), byteArrayOf(0, -1, 127, -128), "signed byte boundaries")
        Check.eq(Hex.decode("DEADBEEF"), Hex.decode("deadbeef"), "case insensitive")
        Check.eq(Hex.encode(byteArrayOf(0, -1, 127, -128)), "00ff7f80", "encode")
        Check.eq(Hex.encode(Hex.decode(LONG_HEX)), LONG_HEX, "round trip")
        Check.ok(!Hex.decode(LONG_HEX).contentEquals(Hex.decode(FLIPPED_HEX)), "one flipped bit differs")
        Check.eq(Hex.decode(LONG_HEX).size, LONG_HEX.length / 2, "length")
        Check.throws("odd length") { Hex.decode("abc") }
        Check.throws("non-hex character") { Hex.decode("00zz") }
        Check.throws("whitespace") { Hex.decode("00 11") }
        val o = obj(read("""{"msg":"","md":"0a1b"}"""))
        Check.eq(o.hex("msg"), ByteArray(0), "empty hex field is a zero-length value")
        Check.eq(o.hex("md"), byteArrayOf(0x0a, 0x1b), "hex field")
        Check.ok(o.hexOrNull("nope") == null, "hexOrNull")
    }

    /** A group with 300 cases must yield 300 cases: an off-by-one in the element loop is silent. */
    test("large arrays keep every element") {
        val doc = (0 until 300).joinToString(",", """{"testGroups":[""", "]}") { """{"tcId":$it}""" }
        val groups = Json(StringReader(doc)).arrayAt("testGroups").toList()
        Check.eq(groups.size, 300, "element count")
        Check.eq(obj(groups[299]).int("tcId"), 299, "last element")
    }
}

private fun read(text: String): Any? = Json(StringReader(text)).readValue()

@Suppress("UNCHECKED_CAST")
private fun obj(value: Any?): Obj = value as Obj

private const val LONG_HEX =
    "d5ba1b2e3f4c5d6e7f8091a2b3c4d5e6" + "f708192a3b4c5d6e7f8091a2b3c4d5e6" +
        "0123456789abcdeffedcba98765432" + "100f1e2d3c4b5a69788796a5b4c3d2e1f0"

/** [LONG_HEX] with the low bit of its last byte set: `f0` → `f1`, one bit and nothing else. */
private const val FLIPPED_HEX =
    "d5ba1b2e3f4c5d6e7f8091a2b3c4d5e6" + "f708192a3b4c5d6e7f8091a2b3c4d5e6" +
        "0123456789abcdeffedcba98765432" + "100f1e2d3c4b5a69788796a5b4c3d2e1f1"
