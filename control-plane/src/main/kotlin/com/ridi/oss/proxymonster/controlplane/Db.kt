package com.ridi.oss.proxymonster.controlplane

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.flywaydb.core.Flyway
import javax.sql.DataSource

/**
 * The control-plane Postgres store: a pooled DataSource with Flyway migrations applied at
 * startup. The proxy and UI share this store (DESIGN.md); migrations live under
 * resources/db/migration.
 */
class Db(config: Config) {
    val dataSource: DataSource = HikariDataSource(
        HikariConfig().apply {
            jdbcUrl = config.dbUrl
            username = config.dbUser
            password = config.dbPassword
            driverClassName = "org.postgresql.Driver"
            poolName = "pm-control-plane"
            maximumPoolSize = 10
        },
    )

    /**
     * Apply pending migrations. Call once at startup before serving traffic.
     *
     * `PM_DB_REPAIR_CHECKSUMS=true` realigns the stored checksums of already-applied migrations to
     * the files on disk before migrating, for the one release that removes the doc paths those files
     * used to carry in their comments. Flyway checksums a migration whole, so editing a comment in an
     * applied file makes validateOnMigrate refuse and the process exit before it serves — which is
     * what the removal does to every database migrated before it.
     *
     * Repair only rewrites `flyway_schema_history` rows; it applies no SQL and touches no schema or
     * data. It is off by default and deliberately not a permanent setting: leaving it on would mean a
     * modified migration silently becomes the new expected state, which is the guarantee this flag
     * exists to restore, not to discard. Turn it on for the upgrade, then remove it.
     */
    fun migrate() {
        val flyway = Flyway.configure()
            .dataSource(dataSource)
            .load()
        if (System.getenv("PM_DB_REPAIR_CHECKSUMS")?.equals("true", ignoreCase = true) == true) {
            flyway.repair()
        }
        flyway.migrate()
    }
}
