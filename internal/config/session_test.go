package config

import "testing"

func TestSessionLifetimeUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name            string
		previous        int
		want            int
		pythonFirst     bool
		pristine        bool
		changedRevision int64
	}{
		{name: "old default", previous: 28800, want: 345600, changedRevision: 1},
		{name: "custom duration", previous: 7200, want: 7200},
		{name: "pristine database still permits legacy import", previous: 28800, want: 345600, pristine: true},
		{name: "Python upgrades shared database", previous: 28800, want: 345600, pythonFirst: true, changedRevision: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, root := t.Context(), t.TempDir()
			store, err := Open(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })

			original, err := store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			phase, revision := "configured", int64(1)
			if tc.pristine {
				phase, revision = "unconfigured", 0
			}
			if _, err := store.db.ExecContext(ctx, `
UPDATE configuration SET settings=json_set(settings, '$.WEB_JWT_TTL_SECONDS', ?), phase=?, revision=?, service_revision=?
WHERE id=1`, tc.previous, phase, revision, revision); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(ctx, "PRAGMA user_version=0"); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			if tc.pythonFirst {
				pythonOracle(t, `
from app.configuration import Store
import sys
snapshot = Store(sys.argv[1]).snapshot()
assert snapshot['values']['WEB_JWT_TTL_SECONDS'] == 345600
`, root)
			}

			upgraded, err := Open(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { upgraded.Close() })
			snapshot, err := upgraded.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := snapshot.Values.Int("WEB_JWT_TTL_SECONDS"); got != tc.want {
				t.Errorf("upgraded lifetime = %d, want %d", got, tc.want)
			}
			if snapshot.Revision != revision+tc.changedRevision || snapshot.ServiceRevision != revision || snapshot.Phase != phase {
				t.Error("migration changed unrelated configuration metadata")
			}
			if snapshot.Values.String("WEB_JWT_SECRET") != original.Values.String("WEB_JWT_SECRET") {
				t.Error("migration rotated the existing signing key")
			}

			if tc.pristine {
				imported, err := upgraded.ImportLegacy(ctx, map[string]string{
					"REALM": "EXAMPLE.TEST", "WORKGROUP": "EXAMPLE", "DOMAIN": "example.test",
					"DOMAIN_USERS_SID": "S-1-5-21-1-513", "DOMAIN_ADMINS_SID": "S-1-5-21-1-512",
				})
				if err != nil || !imported {
					t.Fatalf("could not import legacy settings after upgrade: %v", err)
				}
				return
			}

			if err := upgraded.Save(ctx, Values{"WEB_JWT_TTL_SECONDS": 28800}, snapshot.Revision, false); err != nil {
				t.Fatal(err)
			}
			if err := upgraded.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { reopened.Close() })
			snapshot, err = reopened.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := snapshot.Values.Int("WEB_JWT_TTL_SECONDS"); got != 28800 {
				t.Errorf("restart overwrote the explicit eight-hour setting: %d", got)
			}
		})
	}
}
