package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadParsesYAML(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := cfg.Monitor
	if m.PollInterval != 90*time.Second {
		t.Errorf("poll_interval = %v, want 90s", m.PollInterval)
	}
	if m.SignInterval != time.Hour {
		t.Errorf("sign_interval = %v, want 1h", m.SignInterval)
	}
	if m.FullVerifyInterval != time.Hour {
		t.Errorf("full_verify_interval = %v, want 1h", m.FullVerifyInterval)
	}
	if m.Bucket != "audit-worm-example" {
		t.Errorf("bucket = %q", m.Bucket)
	}
	if m.DBDSNEnv != "AUDITMON_DB_DSN" {
		t.Errorf("db_dsn_env = %q", m.DBDSNEnv)
	}
	if m.Signer.Type != "filekey" || m.Signer.KeyPath != "/var/lib/auditmon/signer.key" {
		t.Errorf("signer = %+v", m.Signer)
	}
	if m.RetentionDays != 730 {
		t.Errorf("retention_days = %d, want 730", m.RetentionDays)
	}
}

func TestEnvOverrideWins(t *testing.T) {
	t.Setenv("AUDITMON_MONITOR_POLL_INTERVAL", "30s")
	t.Setenv("AUDITMON_MONITOR_BUCKET", "override-bucket")
	t.Setenv("AUDITMON_MONITOR_RETENTION_DAYS", "365")

	cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Monitor.PollInterval != 30*time.Second {
		t.Errorf("poll_interval = %v, want the env override 30s", cfg.Monitor.PollInterval)
	}
	if cfg.Monitor.Bucket != "override-bucket" {
		t.Errorf("bucket = %q, want the env override", cfg.Monitor.Bucket)
	}
	if cfg.Monitor.RetentionDays != 365 {
		t.Errorf("retention_days = %d, want the env override 365", cfg.Monitor.RetentionDays)
	}
}

func TestDBDSNResolvesNamedEnvVar(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if _, err := cfg.DBDSN(); err == nil {
		t.Fatal("expected DBDSN to error when the named env var is unset")
	}

	t.Setenv("AUDITMON_DB_DSN", "postgres://reader@localhost:5432/app?sslmode=disable")
	dsn, err := cfg.DBDSN()
	if err != nil {
		t.Fatalf("DBDSN: %v", err)
	}
	if dsn != "postgres://reader@localhost:5432/app?sslmode=disable" {
		t.Errorf("dsn = %q", dsn)
	}
}

func baseValidConfig() *Config {
	return &Config{Monitor: MonitorConfig{
		PollInterval: 90 * time.Second,
		SignInterval: time.Hour,
		Bucket:       "b",
		DBDSNEnv:     "AUDITMON_DB_DSN",
		Signer:       SignerConfig{Type: "filekey", KeyPath: "/k"},
	}}
}

func TestValidateRejectsBadConfigs(t *testing.T) {
	cases := map[string]func(*Config){
		"missing bucket":     func(c *Config) { c.Monitor.Bucket = "" },
		"zero poll interval": func(c *Config) { c.Monitor.PollInterval = 0 },
		"zero sign interval": func(c *Config) { c.Monitor.SignInterval = 0 },
		"bad signer type":    func(c *Config) { c.Monitor.Signer.Type = "hsm" },
		"filekey no path":    func(c *Config) { c.Monitor.Signer = SignerConfig{Type: "filekey"} },
		"kms no key id":      func(c *Config) { c.Monitor.Signer = SignerConfig{Type: "kms"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseValidConfig()
			mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %q", name)
			}
		})
	}

	if err := baseValidConfig().Validate(); err != nil {
		t.Fatalf("base config should be valid: %v", err)
	}
	kms := baseValidConfig()
	kms.Monitor.Signer = SignerConfig{Type: "kms", KeyID: "alias/x"}
	if err := kms.Validate(); err != nil {
		t.Fatalf("kms config should be valid: %v", err)
	}
}

// TestValidateRejectsUnprotectedPerDatasourceThreshold confirms a per_datasource entry with no rows/bytes
// ceiling is rejected at load, since that datasource's entry would override the default and leave it
// unprotected.
func TestValidateRejectsUnprotectedPerDatasourceThreshold(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules.MassExport = MassExportRule{
		Window:        10 * time.Minute,
		Default:       VolumeThreshold{Rows: 100000},
		PerDatasource: map[string]VolumeThreshold{"leaky-ds": {}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected a per_datasource entry with no ceiling to be rejected")
	}

	cfg.Rules.MassExport.PerDatasource = map[string]VolumeThreshold{"leaky-ds": {Rows: 50000}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a per_datasource entry with a ceiling should be valid: %v", err)
	}
}

func TestDBDSNFromDiscreteParameters(t *testing.T) {
	// A deployment already holds host, port, user and password as separate values, so it passes them as
	// separate values. Nothing assembles a connection string by hand, which means there is no second
	// format to keep in step with the control plane's and nothing to parse.
	cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// monitor.yaml names an env var; leave it empty so the parameters are what answer.
	t.Setenv("AUDITMON_DB_DSN", "")
	t.Setenv("AUDITMON_DB_HOST", "db.internal")
	t.Setenv("AUDITMON_DB_PORT", "5432")
	t.Setenv("AUDITMON_DB_NAME", "proxymonster")
	t.Setenv("AUDITMON_DB_USER", "pmadmin")
	t.Setenv("AUDITMON_DB_PASSWORD", "p@ss/word:1")

	dsn, err := cfg.DBDSN()
	if err != nil {
		t.Fatalf("DBDSN: %v", err)
	}
	// The password holds @ / and : — every character that would otherwise end the userinfo early and
	// silently repoint the connection at a different host. They must survive percent-encoded.
	want := "postgres://pmadmin:p%40ss%2Fword%3A1@db.internal:5432/proxymonster?sslmode=require"
	if dsn != want {
		t.Errorf("dsn = %q, want %q", dsn, want)
	}
}

func TestDBDSNDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Setenv("AUDITMON_DB_DSN", "")
	t.Setenv("AUDITMON_DB_HOST", "db.internal")
	t.Setenv("AUDITMON_DB_NAME", "proxymonster")
	t.Setenv("AUDITMON_DB_USER", "pmadmin")
	t.Setenv("AUDITMON_DB_PASSWORD", "x")

	dsn, err := cfg.DBDSN()
	if err != nil {
		t.Fatalf("DBDSN: %v", err)
	}
	// Port defaults to PostgreSQL's, and sslmode to require: a monitor reading an audit trail over a
	// network should not have to be told to encrypt, and pgx would otherwise fall back to preferring.
	if want := "postgres://pmadmin:x@db.internal:5432/proxymonster?sslmode=require"; dsn != want {
		t.Errorf("dsn = %q, want %q", dsn, want)
	}

	t.Setenv("AUDITMON_DB_SSLMODE", "verify-full")
	dsn, err = cfg.DBDSN()
	if err != nil {
		t.Fatalf("DBDSN: %v", err)
	}
	if !strings.Contains(dsn, "sslmode=verify-full") {
		t.Errorf("an explicit sslmode must win, got %q", dsn)
	}
}

func TestDBDSNPrefersAWholeDSNWhenPresent(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Setenv("AUDITMON_DB_DSN", "postgres://reader@localhost:5432/app?sslmode=disable")
	t.Setenv("AUDITMON_DB_HOST", "ignored.internal")
	t.Setenv("AUDITMON_DB_NAME", "ignored")
	t.Setenv("AUDITMON_DB_USER", "ignored")

	dsn, err := cfg.DBDSN()
	if err != nil {
		t.Fatalf("DBDSN: %v", err)
	}
	if dsn != "postgres://reader@localhost:5432/app?sslmode=disable" {
		t.Errorf("an explicit DSN must win over the parameters, got %q", dsn)
	}
}

func TestDBDSNRejectsIncompleteParameters(t *testing.T) {
	// Failing closed with a message that names the missing variable, rather than composing a DSN with an
	// empty database or user and letting pgx report something unrelated at connect time.
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{{
		name: "nothing configured at all",
		env:  map[string]string{},
		want: "AUDITMON_DB_HOST",
	}, {
		name: "host without a database",
		env:  map[string]string{"AUDITMON_DB_HOST": "db.internal", "AUDITMON_DB_USER": "u"},
		want: "AUDITMON_DB_NAME",
	}, {
		name: "host without a user",
		env:  map[string]string{"AUDITMON_DB_HOST": "db.internal", "AUDITMON_DB_NAME": "pm"},
		want: "AUDITMON_DB_USER",
	}, {
		name: "a port that is not a number",
		env: map[string]string{
			"AUDITMON_DB_HOST": "db.internal", "AUDITMON_DB_NAME": "pm",
			"AUDITMON_DB_USER": "u", "AUDITMON_DB_PORT": "postgres",
		},
		want: "AUDITMON_DB_PORT",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(filepath.Join("testdata", "monitor.yaml"))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			for _, k := range []string{
				"AUDITMON_DB_DSN", "AUDITMON_DB_HOST", "AUDITMON_DB_PORT",
				"AUDITMON_DB_NAME", "AUDITMON_DB_USER",
			} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err = cfg.DBDSN()
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should name %s, got: %v", tc.want, err)
			}
		})
	}
}
