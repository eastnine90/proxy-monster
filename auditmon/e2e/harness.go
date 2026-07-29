//go:build e2e

// Package e2e is a rerunnable end-to-end harness that drives the audit monitor's alert rules against a
// LIVE demo stack (wire proxies + control plane + Postgres audit store + MinIO WORM) and asserts each
// alert lands in the WORM alerts/ prefix. It assumes the demo is already up; launch/teardown of the demo
// is out of scope. Everything is 127.0.0.1 on the same host. Run with the E2E tag against the demo:
//
//	AUDITMON_E2E=1 go test -tags e2e -run TestE2E$ -timeout 20m ./e2e/...
//
// Coordinates default to the running demo and are overridable by env for a different instance.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// coords are the live-demo endpoints. Defaults match the running demo; override via env for another instance.
type coords struct {
	pgDSN      string // audit store (audit_event / audit_chain_head live here)
	cpHTTP     string // control-plane HTTP (token mint / seed)
	minioAddr  string // MinIO endpoint host:port
	minioKey   string
	minioSec   string
	wormBucket string
	mysqlProxy string // a MySQL wire proxy host:port (drive decisions)
	pgProxy    string // the PG wire proxy host:port
	pollWait   time.Duration
	// auditmonBin + auditmonCfg locate the monitor's own CLI, so the integrity test can run the operator
	// commands (`verify`, `accept-break`) exactly as a human would rather than reimplementing them.
	auditmonBin string
	auditmonCfg string
}

func demoCoords() coords {
	return coords{
		pgDSN:      env("AUDITMON_E2E_PG_DSN", "postgres://proxymonster:proxymonster@127.0.0.1:44344/proxymonster"),
		cpHTTP:     env("AUDITMON_E2E_CP_HTTP", "http://127.0.0.1:44042"),
		minioAddr:  env("AUDITMON_E2E_MINIO", "127.0.0.1:44900"),
		minioKey:   env("AUDITMON_E2E_MINIO_KEY", "minioadmin"),
		minioSec:   env("AUDITMON_E2E_MINIO_SEC", "minioadmin"),
		wormBucket: env("AUDITMON_E2E_BUCKET", "pm-audit-worm"),
		mysqlProxy: env("AUDITMON_E2E_MYSQL", "127.0.0.1:44775"),
		pgProxy:    env("AUDITMON_E2E_PGPROXY", "127.0.0.1:44059"),
		// One auditmon poll plus slack; the demo monitor polls every 30s.
		pollWait: envDur("AUDITMON_E2E_POLL_WAIT", 40*time.Second),
		// Empty by default: the integrity test skips unless it is told where the monitor's CLI and config
		// live, because running `accept-break` against the wrong deployment is not something to guess at.
		auditmonBin: env("AUDITMON_E2E_BIN", ""),
		auditmonCfg: env("AUDITMON_E2E_CONFIG", ""),
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func mcAlias(c coords) error {
	out, err := exec.Command("mc", "alias", "set", "e2e",
		"http://"+c.minioAddr, c.minioKey, c.minioSec).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mc alias set: %v: %s", err, out)
	}
	return nil
}

// wormAlert is the alert JSON the monitor writes to alerts/<id>.json. Only the fields the harness asserts
// on are decoded; extra fields are ignored.
type wormAlert struct {
	Severity    string  `json:"severity"`
	Rule        string  `json:"rule"`
	Principal   string  `json:"principal"`
	Datasource  string  `json:"datasource"`
	DecisionIDs []int64 `json:"decision_ids"`
	Key         string  `json:"-"` // the object key it was read from
}

// readWormAlerts lists + fetches every alerts/<id>.json object and decodes it. Rerunnable assertions call
// this after resetChain + a poll wait, so it returns only the current run's alerts.
func readWormAlerts(c coords) ([]wormAlert, error) {
	if err := mcAlias(c); err != nil {
		return nil, err
	}
	// mc ls --json lines each carry a "key" relative to the prefix.
	out, err := exec.Command("mc", "ls", "--recursive", "--json",
		fmt.Sprintf("e2e/%s/alerts/", c.wormBucket)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("mc ls alerts/: %v: %s", err, out)
	}
	var alerts []wormAlert
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil || entry.Key == "" {
			continue
		}
		cat, err := exec.Command("mc", "cat",
			fmt.Sprintf("e2e/%s/alerts/%s", c.wormBucket, entry.Key)).Output()
		if err != nil {
			return nil, fmt.Errorf("mc cat %s: %w", entry.Key, err)
		}
		var a wormAlert
		if err := json.Unmarshal(cat, &a); err != nil {
			return nil, fmt.Errorf("decode alert %s: %w", entry.Key, err)
		}
		a.Key = entry.Key
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// rulesFired returns the distinct set of rule names present in the alerts, for readable assertions.
func rulesFired(alerts []wormAlert) []string {
	seen := map[string]struct{}{}
	for _, a := range alerts {
		seen[a.Rule] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
