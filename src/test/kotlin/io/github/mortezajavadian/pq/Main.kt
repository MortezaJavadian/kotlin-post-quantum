package io.github.mortezajavadian.pq

import io.github.mortezajavadian.pq.testing.Case
import io.github.mortezajavadian.pq.testing.Outcome
import io.github.mortezajavadian.pq.testing.Skips
import io.github.mortezajavadian.pq.testing.Suite
import io.github.mortezajavadian.pq.testing.Vectors
import io.github.mortezajavadian.pq.testing.maxCasesPerGroup
import io.github.mortezajavadian.pq.testing.runCase
import kotlin.system.exitProcess

/**
 * Every suite, in the order they should run: cheap and hermetic first.
 *
 * The ordering is deliberate. [io.github.mortezajavadian.pq.testing.jsonSelfTestSuite] needs no files
 * and proves the reader that every later expected value passes through; [basicSuite] needs no files
 * and proves the schemes agree with themselves; only then do the four vector suites spend minutes
 * comparing against NIST and Wycheproof. A broken Keccak or a broken parser is reported in the first
 * second rather than the tenth minute.
 */
internal val ALL_SUITES: List<Suite> = listOf(
    io.github.mortezajavadian.pq.testing.jsonSelfTestSuite,
    basicSuite,
    acvpSha3Suite,
    acvpMlKemSuite,
    acvpMlDsaSuite,
    wycheproofMlKemSuite,
    wycheproofMlDsaSuite,
)

/**
 * The console runner: `java -cp <main>:<test>:<stdlib> io.github.mortezajavadian.pq.MainKt`.
 *
 * `./gradlew test` drives the same suites through JUnit, but this front end needs nothing on the
 * classpath except `kotlin-stdlib`, which is what makes the suite runnable on a machine that cannot
 * reach a Maven repository — the situation this library was validated in.
 *
 * Any arguments are treated as filters matched against `"<suite> / <case>"`, so
 * `… MainKt SHAKE ML-DSA-87` runs a subset. Exit status is 0 only if nothing failed; a skipped case
 * is not a failure, but every skip is named in the summary with its count, because a suite that
 * passed over half its work and said nothing is reporting coverage it does not have.
 */
fun main(args: Array<String>) {
    val filters = args.filterNot { it.startsWith("-") }
    val verbose = args.contains("-v") || args.contains("--verbose")

    println("kotlin-post-quantum test suite")
    println("  vectors:      ${Vectors.root?.path ?: "not found"}")
    println("  required:     ${if (Vectors.required) "yes (PQ_REQUIRE_VECTORS=1)" else "no"}")
    if (maxCasesPerGroup != Int.MAX_VALUE) println("  PQ_MAX_CASES: $maxCasesPerGroup")
    if (filters.isNotEmpty()) println("  filters:      ${filters.joinToString(", ")}")
    println()

    val results = ArrayList<io.github.mortezajavadian.pq.testing.CaseResult>()
    var assertions = 0L
    for (suite in ALL_SUITES) {
        val cases = suite.cases.filter { matches(filters, suite, it) }
        if (cases.isEmpty()) continue
        println(suite.name)
        for (case in cases) {
            val r = runCase(suite.name, case)
            results += r
            assertions += r.assertions
            val mark = when (r.outcome) {
                Outcome.PASSED -> "pass"
                Outcome.FAILED -> "FAIL"
                Outcome.SKIPPED -> "skip"
            }
            val ms = r.nanos / 1_000_000
            println("  [$mark] ${case.name}  (${r.assertions} assertions, ${ms} ms)")
            for (line in r.notes) println("         consumed $line")
            if (r.outcome != Outcome.PASSED && r.detail != null) {
                for (line in r.detail.lines()) println("         $line")
            }
            if (verbose) for ((reason, count) in r.skips) println("         skipped ×$count  $reason")
        }
        println()
    }

    val failed = results.count { it.outcome == Outcome.FAILED }
    val skipped = results.count { it.outcome == Outcome.SKIPPED }
    val passed = results.count { it.outcome == Outcome.PASSED }

    val skips = Skips.snapshot()
    if (skips.isNotEmpty()) {
        println("passed over (${skips.values.sum()} occurrences):")
        for ((reason, count) in skips.entries.sortedByDescending { it.value }) {
            println("  ×$count  $reason")
        }
        println()
    }

    println("$passed passed, $failed failed, $skipped skipped — $assertions assertions")
    if (results.isEmpty()) {
        println("no cases matched — refusing to report success")
        exitProcess(2)
    }
    exitProcess(if (failed > 0) 1 else 0)
}

private fun matches(filters: List<String>, suite: Suite, case: Case): Boolean =
    filters.isEmpty() || filters.any { f ->
        "${suite.name} / ${case.name}".contains(f, ignoreCase = true)
    }
