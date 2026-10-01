// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"testing"
)

func TestMariaDBOptionFileSupported_BoundedShapes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw string
		supported bool
		invalid   bool
	}{
		{"mariadb-on", "[mariadb]\ninnodb_defragment=ON\n", true, false},
		{"mariadbd-off", "[mariadbd]\ninnodb_defragment=OFF\n", true, false},
		{"mysqld-bare", "[mysqld]\ninnodb_defragment\n", true, false},
		{"server-absent", "[server]\nmax_connections=10\n", true, false},
		{"server-after-client", "[client]\nuser=private\n[server]\nmax_connections=10\n", true, false},
		{"no-server-group", "[client]\nuser=private\n", false, false},
		{"comments-only", "# private\n; private\n", false, false},
		{"include", "!includedir /private/mysql\n[mariadbd]\nmax_connections=10\n", false, false},
		{"hyphen-alias", "[mariadbd]\ninnodb-defragment=ON\n", false, false},
		{"loose-hyphen", "[mariadbd]\nloose-innodb_defragment=ON\n", false, false},
		{"loose-underscore", "[mariadbd]\nloose_innodb_defragment=ON\n", false, false},
		{"skip-prefix", "[mariadbd]\nskip-innodb_defragment\n", false, false},
		{"enable-prefix", "[mariadbd]\nenable-innodb-defragment\n", false, false},
		{"maximum-prefix", "[mariadbd]\nmaximum-innodb-defragment=1\n", false, false},
		{"nested-prefix", "[mariadbd]\nskip-loose-innodb-defragment\n", false, false},
		{"case-alias", "[mariadbd]\nINNODB_DEFRAGMENT=ON\n", false, false},
		{"unsupported-value", "[mariadbd]\ninnodb_defragment=private\n", false, false},
		{"versioned-group", "[mariadbd-11.4]\ninnodb_defragment=ON\n", false, false},
		{"group-trailing-comment", "[mariadbd] # selected\ninnodb_defragment=ON\n", false, false},
		{"unknown-group", "[galera]\nwsrep_on=ON\n", false, false},
		{"unreviewed-space-value", "[mariadbd]\nmax_connections 10\n", false, false},
		{"malformed-group", "[mariadbd\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			supported, err := mariaDBOptionFileSupported([]byte(tc.raw))
			if (err != nil) != tc.invalid || supported != tc.supported {
				t.Fatalf("supported=%t err=%v", supported, err)
			}
		})
	}
}

func TestPrepareMariaDBEffectiveConfig_RequiresExplicitBehaviorIntent(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw                                      string
		complete, precedence, upstream, declared, need bool
		wantState, wantReason                          string
		wantFact                                       string
	}{
		{"required-on", "[mariadb]\ninnodb_defragment=ON\n", true, true, true, true, true, "PREPARED", "MARIADB_DEFRAGMENTATION_REQUIREMENT_PREPARED", `"boolValue":true`},
		{"required-absent", "[server]\nmax_connections=10\n", true, true, true, true, true, "PREPARED", "MARIADB_DEFRAGMENTATION_REQUIREMENT_PREPARED", `"boolValue":true`},
		{"waived-off", "[mariadbd]\ninnodb_defragment=OFF\n", true, true, true, true, false, "PREPARED", "MARIADB_DEFRAGMENTATION_REQUIREMENT_PREPARED", `"boolValue":false`},
		{"on-without-intent", "[mariadb]\ninnodb_defragment=ON\n", true, true, true, false, false, "UNKNOWN", "MARIADB_EFFECTIVE_CONFIG_DECLARATIONS_INCOMPLETE", `"state":"unsupported"`},
		{"missing-upstream", "[server]\nmax_connections=10\n", true, true, false, true, false, "UNKNOWN", "MARIADB_EFFECTIVE_CONFIG_DECLARATIONS_INCOMPLETE", `"boolValue":false`},
		{"include-unknown", "!include /private/my.cnf\n[mariadb]\nmax_connections=10\n", true, true, true, true, false, "UNKNOWN", "MARIADB_OPTION_FILE_SHAPE_UNSUPPORTED", `"state":"unsupported"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prepared, err := PrepareMariaDBEffectiveConfig([]byte(tc.raw), MariaDBFrom, MariaDBTo, tc.complete, tc.precedence, tc.upstream, tc.declared, tc.need)
			if err != nil || prepared.State != tc.wantState || prepared.Reason != tc.wantReason || !bytes.Contains(prepared.CanonicalInputJSON, []byte(tc.wantFact)) {
				t.Fatalf("prepared=%+v input=%s err=%v", prepared, prepared.CanonicalInputJSON, err)
			}
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("private")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("max_connections")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("innodb_defragment=ON")) {
				t.Fatal("raw MariaDB configuration leaked into canonical input")
			}
		})
	}
	wrong, err := PrepareMariaDBEffectiveConfig([]byte("[mariadb]\ninnodb_defragment=ON\n"), "10.11.7", MariaDBTo, true, true, true, true, true)
	if err != nil || wrong.State != "UNKNOWN" || wrong.Reason != "UNSUPPORTED_VERSION_PAIR" {
		t.Fatalf("wrong pair=%+v err=%v", wrong, err)
	}
}
