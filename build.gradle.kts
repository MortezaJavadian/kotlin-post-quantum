import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.0.21"
    `java-library`
    // 0.35.0 and deliberately not a newer one: 0.36.0 raised the plugin's floor to Gradle 9.0 and
    // Kotlin Gradle Plugin 2.2, and this project is Gradle 8.13 + Kotlin 2.0.21. 0.35.0's own floor is
    // Gradle 8.13 — exactly the wrapper committed here — so it is the newest version this build can run.
    id("com.vanniktech.maven.publish") version "0.35.0"
}

group = "io.github.mortezajavadian"

// No `-SNAPSHOT`. A Maven Central *release* is permanent: once `0.1.0` is published these coordinates
// can never be uploaded again, not even to correct a mistake. So this number is bumped for every
// release, and a version under test stays unpublished rather than being re-released.
version = "0.1.0"

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

    // Every declaration in `src/main` must state its visibility and its return type explicitly. On a
    // library this is not a style rule: without it, a `val` or `fun` written with no modifier is public
    // by default, so the published surface grows by omission. With it, exporting something is a
    // decision someone typed. The whole of src/main already satisfies this — turning it on adds no
    // source change, it only stops the next accidental export from compiling.
    explicitApi()

    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
    }
}

// `-Xjdk-release=1.8` on the *published* compilation only.
//
// `jvmTarget = 1.8` sets the class-file version and nothing else: the compiler still resolves against
// the toolchain's JDK 17 class library, so a call to a Java 9+ method compiles happily and then throws
// NoSuchMethodError on a Java 8 or older-Android runtime. `-Xjdk-release` makes the compiler resolve
// against the real Java 8 API signatures, which turns that runtime failure into a compile error.
//
// Scoped to compileKotlin rather than set in `kotlin.compilerOptions`, because the test sources are
// never published and run on the toolchain JDK — holding them to the Java 8 API would be a constraint
// with nothing behind it.
tasks.named<KotlinCompile>("compileKotlin") {
    compilerOptions {
        freeCompilerArgs.add("-Xjdk-release=1.8")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    // Set explicitly, and load-bearing for consumers: Gradle would otherwise infer
    // `org.gradle.jvm.version` from the toolchain and publish 17 in the module metadata, which makes
    // variant-aware resolution reject this library on any project targeting Java 8 or 11 — a hard
    // failure at dependency resolution, before a line of it runs.
    targetCompatibility = JavaVersion.VERSION_1_8
    // `withSourcesJar()` is deliberately gone: the publishing plugin registers its own `sourcesJar`
    // (see the KotlinJvm platform below) and two tasks writing one `-sources.jar` fail the build.
}

tasks.jar {
    manifest {
        attributes(
            mapOf(
                // What a JPMS consumer gets as the module name for this automatic module. Pinning it
                // matters because the fallback is derived from the *file name*, so without this line
                // `require kotlin.post.quantum;` would change meaning if the artifact were ever renamed.
                "Automatic-Module-Name" to "io.github.mortezajavadian.pq",
                "Implementation-Title" to "kotlin-post-quantum",
                "Implementation-Version" to project.version.toString(),
            ),
        )
    }
}

tasks.withType<Jar>().configureEach {
    // A byte-identical jar for identical sources. Both defaults leak the machine that built it — file
    // timestamps and the filesystem's directory order — which means two builds of the same commit
    // produce two different SHA-1s and nobody downstream can check that the published artifact was
    // built from the published tag.
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    // MIT, in the jar and in the sources jar. The POM names the licence for tooling; a copy inside the
    // artifact is what survives being vendored, shaded or repackaged, which is the case that matters.
    // Named as one file rather than `from(rootDir) { include("LICENSE") }`, which would make the whole
    // repository — test-vectors/ included, 63 MB of it — an input to every jar task.
    from(layout.projectDirectory.file("LICENSE")) {
        into("META-INF")
    }
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
    // …and that line is not enough on its own. `Test` is a @CacheableTask and gradle.properties sets
    // org.gradle.caching=true, so the build cache is consulted *after* up-to-date checking fails and
    // restores the previous run's results without executing anything — the same false green reached
    // through the other door, and this one travels between machines. Opting the task out closes it.
    outputs.cacheIf { false }
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

/**
 * Publication to Maven Central through the Central Portal (`central.sonatype.com`).
 *
 * Two commands come out of this block:
 *
 *   ./gradlew publishToMavenCentral            uploads a deployment; nothing is public until the
 *                                              "Publish" button is pressed in the Portal
 *   ./gradlew publishAndReleaseToMavenCentral   uploads and releases in one go
 *
 * and one rehearsal that never leaves the machine:
 *
 *   ./gradlew publishToMavenLocal              writes the whole artifact set to ~/.m2/repository
 *
 * Credentials are never in this file. `mavenCentralUsername` / `mavenCentralPassword` (a Portal *user
 * token*, not the login) and the `signing.*` keys belong in `~/.gradle/gradle.properties`, outside the
 * repository.
 */
mavenPublishing {
    // Upload and stop. `publishToMavenCentral(automaticRelease = true)` would release straight from the
    // command line; leave it off at least until one deployment has been through the Portal by hand,
    // because releasing is the irreversible half — a released version cannot be replaced or deleted,
    // while an unreleased deployment can be dropped and re-uploaded as often as needed.
    publishToMavenCentral()

    // Central rejects unsigned artifacts outright. This attaches a `.asc` to the jar, the sources jar,
    // the javadoc jar, the POM and the Gradle module metadata, using the GPG key named by the
    // `signing.*` properties. The public half of that key must be on a keyserver before the upload:
    // "public key not found" during validation is the single most common first-deployment failure.
    signAllPublications()

    // groupId, artifactId, version. `io.github.<user>` is the namespace that Central verifies against
    // ownership of the GitHub account, which is why the package names are what they are.
    coordinates(project.group.toString(), "kotlin-post-quantum", project.version.toString())

    // A real sources jar, and an empty javadoc jar.
    //
    // The sources jar is the documentation here: every parameter, hazard and FIPS clause lives in KDoc
    // next to the code it describes, and a consumer's IDE reads it from this artifact. The javadoc jar
    // has to *exist* for Central's validation to pass but does not have to contain anything, and
    // rendering HTML from KDoc needs Dokka — a second plugin with its own version matrix against
    // Kotlin 2.0.21. `Empty()` is also what this plugin already defaults to for Kotlin/JVM; it is
    // written out so the choice is visible rather than inherited.
    configure(KotlinJvm(javadocJar = JavadocJar.Empty(), sourcesJar = true))

    pom {
        name.set("kotlin-post-quantum")
        description.set(
            "ML-KEM (FIPS 203) and ML-DSA (FIPS 204) for the JVM, with the FIPS 202 SHA-3 and SHAKE " +
                "they are built on. A line-by-line Kotlin port of noble-post-quantum, no dependencies, " +
                "validated against NIST ACVP and Wycheproof vectors.",
        )
        inceptionYear.set("2026")
        url.set("https://github.com/MortezaJavadian/kotlin-post-quantum")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
                distribution.set("https://opensource.org/licenses/MIT")
            }
        }
        developers {
            developer {
                id.set("MortezaJavadian")
                name.set("Morteza Javadian")
                url.set("https://github.com/MortezaJavadian")
            }
        }
        scm {
            url.set("https://github.com/MortezaJavadian/kotlin-post-quantum")
            connection.set("scm:git:git://github.com/MortezaJavadian/kotlin-post-quantum.git")
            developerConnection.set("scm:git:ssh://git@github.com/MortezaJavadian/kotlin-post-quantum.git")
        }
    }
}
