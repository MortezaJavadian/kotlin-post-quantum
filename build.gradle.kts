import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.0.21"
    `java-library`
}

group = "io.github.mortezajavadian"
version = "0.1.0-SNAPSHOT"

dependencies {
    // Declared by coordinate rather than through kotlin("test"). The test sources import exactly two
    // things from a framework — org.junit.jupiter.api.* for the @TestFactory front end and
    // org.opentest4j.TestAbortedException for "skipped" — and nothing from kotlin.test, so the
    // variant-aware kotlin-test → kotlin-test-junit5 selection buys nothing here and would leave the
    // Jupiter *engine* undeclared. useJUnitPlatform() needs the engine on the test runtime classpath;
    // without it Gradle fails the run with "no test engine" or, worse, finds zero tests and is green.
    testImplementation(platform("org.junit:junit-bom:5.10.3"))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    // opentest4j arrives transitively with junit-jupiter-api, but PqVectorsTest imports it directly,
    // so it is named directly.
    testImplementation("org.opentest4j:opentest4j:1.3.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    // Required explicitly from Gradle 9 on, harmless before it.
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    // Built with a modern JDK, but emitting Java 8 bytecode: the schemes use nothing newer than
    // BigInteger and SecureRandom, and 1.8 is the one target every Android and JVM consumer accepts.
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
    withSourcesJar()
}

tasks.test {
    useJUnitPlatform()
    // The ACVP suites are long-running and worth watching; a silent test task hides which of them
    // actually ran, and a validation run that cannot be seen is not a validation run.
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
    // The vectors live in test-vectors/, which is not a declared input to this task — nothing in the
    // build model knows they exist. Left up-to-date-checked, `./gradlew test` after fetching a newer
    // pin would report UP-TO-DATE, run nothing, and print a green summary of the previous run: the
    // exact false green this suite is built to prevent. A validation suite always runs.
    outputs.upToDateWhen { false }
    // SHAKE's prompt.json is hundreds of megabytes. Json streams it rather than materialising it, so
    // this is headroom rather than a requirement — but the failure mode of getting it wrong is an
    // OutOfMemoryError two suites in.
    maxHeapSize = "2g"
    // Forwarded explicitly. A Test task inherits the daemon's environment anyway, so these three
    // already reach the fork; naming them documents the knobs and keeps them working if that ever
    // stops being true.
    for (name in listOf("PQ_VECTORS", "PQ_REQUIRE_VECTORS", "PQ_MAX_CASES")) {
        System.getenv(name)?.let { environment(name, it) }
    }
}

/**
 * `./gradlew vectors` — the same suites through the bare `main()` front end.
 *
 * It exists because the two front ends are the check on each other: they share every suite, case and
 * assertion, so a disagreement between them is a harness bug. This one also prints the per-case
 * assertion counts and the full "passed over" table, which is the part of a validation run worth
 * reading, and it takes filters — `./gradlew vectors --args="SHAKE ML-DSA-87"`.
 */
tasks.register<JavaExec>("vectors") {
    group = "verification"
    description = "Runs the vector suites through the standalone main() runner."
    mainClass.set("io.github.mortezajavadian.pq.MainKt")
    classpath = sourceSets["test"].runtimeClasspath
    maxHeapSize = "2g"
    // A non-zero exit from main() must fail the build; JavaExec's default is to do exactly that, and
    // it is spelled out here because main() reports failure only through its exit status.
    isIgnoreExitValue = false
}
