package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestFixedSuite(t *testing.T) {
	root := os.Getenv("RADOS_R06_FIXTURE_ROOT")
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
	if rows := strings.Count(output.String(), "\n"); rows != 11 {
		t.Fatalf("records=%d", rows)
	}
}

func TestRejectsUnknownAndTrailingRequest(t *testing.T) {
	for _, input := range []string{`{"unknown":true}`, `{}`, `{} {}`} {
		if err := run(strings.NewReader(input), &bytes.Buffer{}, os.Getenv("RADOS_R06_FIXTURE_ROOT")); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}
