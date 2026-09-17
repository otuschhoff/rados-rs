package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCanonicalSuite(t *testing.T) {
	root := os.Getenv("RADOS_R04_FIXTURE_ROOT")
	if root == "" {
		root = "fixtures"
	}
	request, err := expectedRequest(root)
	if err != nil {
		t.Fatal(err)
	}
	requestData, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(bytes.NewReader(requestData), &output, root); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(output.String(), "\n"); lines != maxRecords {
		t.Fatalf("result records = %d, want %d", lines, maxRecords)
	}
}

func TestRejectsOversizedUnknownStaleAndExtraRequests(t *testing.T) {
	root := os.Getenv("RADOS_R04_FIXTURE_ROOT")
	if root == "" {
		root = "fixtures"
	}
	if err := run(strings.NewReader(strings.Repeat(" ", maxRecordBytes+1)), &bytes.Buffer{}, root); err == nil {
		t.Fatal("oversized request passed")
	}
	for _, requestData := range []string{`{"schema_version":1,"unknown":true}`, `{}`, `{} {}`} {
		if err := run(strings.NewReader(requestData), &bytes.Buffer{}, root); err == nil {
			t.Fatalf("invalid request passed: %s", requestData)
		}
	}
}
