package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCanonicalSuite(t *testing.T) {
	requestData, err := json.Marshal(expectedRequest())
	if err != nil {
		t.Fatal(err)
	}
	fixtureRoot := os.Getenv("RADOS_R03_FIXTURE_ROOT")
	if fixtureRoot == "" {
		fixtureRoot = "testdata"
	}
	var output bytes.Buffer
	if err := run(bytes.NewReader(requestData), &output, fixtureRoot); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(output.String(), "\n"); lines != maxRecords {
		t.Fatalf("result records = %d, want %d", lines, maxRecords)
	}
}

func TestRejectsOversizedUnknownStaleAndExtraRequests(t *testing.T) {
	if err := run(strings.NewReader(strings.Repeat(" ", maxRecordBytes+1)), &bytes.Buffer{}, "testdata"); err == nil {
		t.Fatal("oversized request passed")
	}
	for _, requestData := range []string{
		`{"schema_version":1,"unknown":true}`,
		`{} {}`,
		`{"schema_version":1}`,
	} {
		if err := run(strings.NewReader(requestData), &bytes.Buffer{}, "testdata"); err == nil {
			t.Fatalf("invalid request passed: %s", requestData)
		}
	}
}
