package audit

import (
	"context"
	"database/sql"
	"testing"

	opdb "github.com/openpass/api/internal/db"
)

func TestRecordAndListAuditEntries(t *testing.T) {
	database := testDB(t)
	service := New(database)

	if err := service.Record(context.Background(), Entry{
		KeyPrefix:  "op_live_abcd1234",
		IPAddress:  "203.0.113.9",
		UserAgent:  "claude-code/1.2",
		Method:     "GET",
		Endpoint:   "/api/v1/vaults",
		StatusCode: 200,
		DurationMS: 12,
		Result:     "success",
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	logs, err := service.List(context.Background(), Filter{KeyPrefix: "op_live_abcd1234"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len(logs) = %d, want 1", len(logs))
	}
	if logs[0].RequestID == "" {
		t.Fatalf("RequestID was not generated")
	}
	if logs[0].UserAgent != "claude-code/1.2" {
		t.Fatalf("UserAgent = %q", logs[0].UserAgent)
	}
}

func TestListFiltersByResult(t *testing.T) {
	database := testDB(t)
	service := New(database)

	for _, result := range []string{"success", "denied"} {
		if err := service.Record(context.Background(), Entry{
			Method:     "GET",
			Endpoint:   "/api/v1/auth/me",
			StatusCode: 401,
			Result:     result,
		}); err != nil {
			t.Fatalf("Record(%s) error = %v", result, err)
		}
	}

	logs, err := service.List(context.Background(), Filter{Result: "denied"})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(logs) != 1 || logs[0].Result != "denied" {
		t.Fatalf("logs = %+v, want one denied entry", logs)
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := opdb.Open(":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := opdb.Migrate(database, opdb.CoreSchema); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return database
}
