package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixtureRoot() string {
	if value := os.Getenv("RADOS_R05_FIXTURE_ROOT"); value != "" {
		return value
	}
	return "fixtures"
}

func TestCanonicalSuite(t *testing.T) {
	root := fixtureRoot()
	request, err := expectedRequest(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(bytes.NewReader(data), &output, root); err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(output.String(), "\n"); count != maxRecords {
		t.Fatalf("records = %d, want %d", count, maxRecords)
	}
}

func TestRejectsOversizedUnknownStaleAndTrailingRequests(t *testing.T) {
	root := fixtureRoot()
	for _, data := range []string{strings.Repeat(" ", maxRecordBytes+1), `{"schema_version":1,"unknown":true}`, `{}`, `{} {}`} {
		if err := run(strings.NewReader(data), &bytes.Buffer{}, root); err == nil {
			t.Fatalf("invalid request passed: %.40s", data)
		}
	}
}
