package config

import (
	"os"
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
}

func TestEnvOverrideWins(t *testing.T) {
	t.Setenv("AUDITMON_MONITOR_POLL_INTERVAL", "30s")
	t.Setenv("AUDITMON_MONITOR_BUCKET", "override-bucket")

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

func TestLoadWithoutAConfigFile(t *testing.T) {
	// The image ships no config on purpose, so a deployment that supplies everything through
	// AUDITMON_* has no file to mount. This is the case that crash-looped the ECS task: Load hard-failed
	// on the absent default path before the env overlay was ever applied, so the monitor exited every
	// ~50s while the service reported "running".
	t.Setenv("AUDITMON_MONITOR_POLL_INTERVAL", "90s")
	t.Setenv("AUDITMON_MONITOR_SIGN_INTERVAL", "1h")
	t.Setenv("AUDITMON_MONITOR_BUCKET", "audit-worm")
	t.Setenv("AUDITMON_MONITOR_SIGNER_TYPE", "kms")
	t.Setenv("AUDITMON_MONITOR_SIGNER_KEY_ID", "alias/pm-audit-signer")

	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("an absent config file must not fail the load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("env-only configuration must validate: %v", err)
	}
	if cfg.Monitor.Bucket != "audit-worm" {
		t.Errorf("bucket = %q, want the env value", cfg.Monitor.Bucket)
	}
	if cfg.Monitor.PollInterval.String() != "1m30s" {
		t.Errorf("poll_interval = %v, want 90s from the env overlay", cfg.Monitor.PollInterval)
	}
}

func TestLoadStillFailsOnAMalformedConfigFile(t *testing.T) {
	// Tolerating an ABSENT file must not tolerate a BROKEN one: a file the operator meant to provide and
	// got wrong has to fail closed, or a typo silently boots on defaults.
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("monitor: [this is not a mapping\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected a malformed config file to fail the load")
	}
}

func TestValidateRejectsEnvOnlyConfigThatIsIncomplete(t *testing.T) {
	// The absent-file path leans entirely on Validate to catch what the overlay left out — without that,
	// a missing file plus a missing variable would boot a half-configured monitor.
	t.Setenv("AUDITMON_MONITOR_POLL_INTERVAL", "90s")
	t.Setenv("AUDITMON_MONITOR_SIGN_INTERVAL", "1h")
	// no bucket, no signer

	// Load validates before returning, so the incompleteness surfaces there rather than from a separate
	// Validate call — an absent file cannot boot a half-configured monitor.
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("expected a configuration with no bucket and no signer to be rejected")
	}
	if !strings.Contains(err.Error(), "bucket") {
		t.Errorf("error should name the missing setting, got: %v", err)
	}
}

func TestEveryDefaultableSettingHasADefault(t *testing.T) {
	// A deployment should have to supply only what is install-specific. Everything with a sane default
	// gets one, so a missing knob cannot be the reason an audit monitor fails to start — that failure
	// looks identical to "nothing to report".
	t.Setenv("AUDITMON_MONITOR_BUCKET", "audit-worm")

	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("bucket alone should be enough to boot: %v", err)
	}
	// The documented cadences (INSTALL.md, README).
	if cfg.Monitor.PollInterval != 90*time.Second {
		t.Errorf("poll_interval = %v, want the 90s default", cfg.Monitor.PollInterval)
	}
	if cfg.Monitor.SignInterval != time.Hour {
		t.Errorf("sign_interval = %v, want the 1h default", cfg.Monitor.SignInterval)
	}
	if cfg.Monitor.FullVerifyInterval != time.Hour {
		t.Errorf("full_verify_interval = %v, want the 1h default", cfg.Monitor.FullVerifyInterval)
	}
	// The signer falls back to filekey, never kms: a kms default would be a key id this install does not
	// own, and signing an anchor with the wrong key is worse than signing with a local one.
	if cfg.Monitor.Signer.Type != "filekey" {
		t.Errorf("signer.type = %q, want the filekey default", cfg.Monitor.Signer.Type)
	}
	if cfg.Monitor.Signer.KeyPath == "" {
		t.Error("the filekey default must come with a key_path, or Validate rejects it")
	}
}

func TestBucketRemainsRequired(t *testing.T) {
	// The one setting with no defensible default: guessing a bucket name would either fail at write time
	// or, worse, write an install's audit anchors into a bucket it does not own.
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected a config with no bucket to be rejected")
	} else if !strings.Contains(err.Error(), "bucket") {
		t.Errorf("error should name the bucket, got: %v", err)
	}
}

func TestExplicitValuesWinOverDefaults(t *testing.T) {
	// Defaults must not shadow configuration — the ECS task passes several of these explicitly.
	t.Setenv("AUDITMON_MONITOR_BUCKET", "audit-worm")
	t.Setenv("AUDITMON_MONITOR_POLL_INTERVAL", "5s")
	t.Setenv("AUDITMON_MONITOR_SIGN_INTERVAL", "30s")
	t.Setenv("AUDITMON_MONITOR_SIGNER_TYPE", "kms")
	t.Setenv("AUDITMON_MONITOR_SIGNER_KEY_ID", "alias/pm-audit-signer")

	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Monitor.PollInterval != 5*time.Second || cfg.Monitor.SignInterval != 30*time.Second {
		t.Errorf("explicit intervals lost: poll=%v sign=%v", cfg.Monitor.PollInterval, cfg.Monitor.SignInterval)
	}
	if cfg.Monitor.Signer.Type != "kms" || cfg.Monitor.Signer.KeyID != "alias/pm-audit-signer" {
		t.Errorf("explicit kms signer lost: %+v", cfg.Monitor.Signer)
	}
	// The filekey default key_path must NOT be filled in for a kms signer.
	if cfg.Monitor.Signer.KeyPath != "" {
		t.Errorf("key_path = %q, want empty for a kms signer", cfg.Monitor.Signer.KeyPath)
	}
}
