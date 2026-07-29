package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.classification.SystemClassificationStore
import com.ridi.oss.proxymonster.controlplane.support.SharedMySql
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.assertServerSeries
import com.ridi.oss.proxymonster.controlplane.support.imageSeries
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `db-support.json` declares which database versions proxy-monster supports. Three things have to agree
 * with it or the support claim is fiction: the engine's bundled classification manifests (a target
 * series with no manifest gets the version-independent fallback, silently losing its version-specific
 * system-catalog tags), the CI matrix (an undeclared version is never actually run), and the test
 * infrastructure's defaults. This test is what makes disagreement a build failure rather than something
 * discovered when a customer points a proxy at an untested server.
 */
class DbSupportMatrixTest {
    private data class Supported(val engine: String, val series: String, val image: String)

    private val repoRoot: Path = Path.of("..").toAbsolutePath().normalize()

    private fun read(role: String): List<Supported> {
        val text = repoRoot.resolve("db-support.json").readText()
        return Json.parseToJsonElement(text).jsonObject[role]!!.jsonArray.map {
            val o = it.jsonObject
            Supported(
                o["engine"]!!.jsonPrimitive.content,
                o["series"]!!.jsonPrimitive.content,
                o["image"]!!.jsonPrimitive.content,
            )
        }
    }

    @Test
    fun `every supported target series has a bundled classification manifest and vice versa`() {
        val declared = read("target").map { it.engine to it.series }.toSet()
        // The engines to look up are the ones the classifier actually ships, NOT the ones `declared`
        // mentions: deriving them from `declared` would make deleting an engine's last target entry hide
        // its manifests from the comparison instead of failing it.
        val store = SystemClassificationStore.load()
        val bundled = listOf("mysql", "postgres")
            .flatMap { engine -> store.classifiersForEngine(engine).map { engine to it.manifest.series } }
            .toSet()

        // Both directions. A declared-but-unbundled series claims support the classifier cannot back;
        // a bundled-but-undeclared series is curated code that no CI leg exercises.
        assertEquals(
            declared,
            bundled,
            "db-support.json target versions and the bundled system-classification manifests disagree — " +
                "declared-not-bundled=${declared - bundled}, bundled-not-declared=${bundled - declared}",
        )
    }

    @Test
    fun `every declared version pins an image of that same series`() {
        // The live-server check compares against the image's series, so an entry whose image disagrees
        // with its own `series` field would pass every gate while running — and claiming a pass for — a
        // different version than it declares. An image with no version in its tag ("latest") is refused
        // for the same reason: nothing could be verified.
        for (role in listOf("target", "storage")) {
            for (entry in read(role)) {
                val fromImage = imageSeries(entry.image)
                assertEquals(
                    entry.series,
                    fromImage,
                    "$role ${entry.engine} declares series ${entry.series} but its image ${entry.image} " +
                        "names ${fromImage ?: "no series at all"}",
                )
            }
        }
    }

    @Test
    fun `storage engines are postgres only`() {
        // The control-plane store SQL is Postgres-specific (RETURNING, ON CONFLICT, jsonb, :: casts), so
        // a non-Postgres storage entry would be a support claim no store query can honor.
        val engines = read("storage").map { it.engine }.distinct()
        assertEquals(listOf("postgres"), engines, "the control-plane store is Postgres-only")
    }

    @Test
    fun `the CI matrix runs exactly the declared versions`() {
        // The matrix is generated from db-support.json at CI time, so no workflow spells the versions
        // out. What this checks is the plumbing that carries a version into a leg: the per-leg
        // environment variables the test infrastructure reads, and the file the matrix is built from.
        // Without them a leg would run whatever the defaults are, for every version, and report a pass
        // for each.
        val workflows = repoRoot.resolve(".github/workflows").toFile()
            .listFiles { f -> f.extension == "yml" || f.extension == "yaml" }
            ?.map { it.readText() }
            .orEmpty()
        // A missing directory yields an empty list, and every `any` below would then be vacuously
        // false — but assert presence explicitly so the failure names the real cause.
        assertTrue(workflows.isNotEmpty(), "expected at least one workflow under .github/workflows")

        assertTrue(
            workflows.any { it.contains("db-support.json") },
            "no workflow reads db-support.json — the CI matrix would not follow the declared version set",
        )
        for (envVar in listOf("PM_TEST_POSTGRES_IMAGE", "PM_TEST_MYSQL_IMAGE")) {
            assertTrue(
                workflows.any { it.contains(envVar) },
                "no workflow sets $envVar — its legs would all run the default version",
            )
        }
        // Docker-less Testcontainers tests skip, and a skipped suite reports success. CI has to opt
        // into the hard failure or a leg can pass having run nothing.
        assertTrue(
            workflows.any { it.contains("PM_REQUIRE_DB_TESTS") },
            "no workflow sets PM_REQUIRE_DB_TESTS — a Docker-less leg would pass by skipping",
        )
    }

    @Test
    fun `the shared test containers default to a declared version`() {
        val images = (read("target") + read("storage")).map { it.image }.toSet()
        // These read PM_TEST_*_IMAGE, so under a matrix leg this asserts the leg pinned a declared
        // version, and on a plain local run it asserts the default is one.
        assertTrue(SharedPostgres.IMAGE in images, "SharedPostgres.IMAGE=${SharedPostgres.IMAGE} is not a declared supported version")
        assertTrue(SharedMySql.IMAGE in images, "SharedMySql.IMAGE=${SharedMySql.IMAGE} is not a declared supported version")
    }

    @Test
    fun `the running servers are the versions the images asked for`() {
        requireDockerOrSkip()
        // The check above proves the CONFIGURED version is supported; this one proves the server the
        // tests actually talked to is that version. A container reused from a different image, or a tag
        // that resolved elsewhere, would otherwise let a leg report a pass for a version it never ran.
        assertServerSeries(SharedPostgres.IMAGE, imageSeries(SharedPostgres.IMAGE), SharedPostgres.serverSeries())
        assertServerSeries(SharedMySql.IMAGE, imageSeries(SharedMySql.IMAGE), SharedMySql.serverSeries())
    }
}
