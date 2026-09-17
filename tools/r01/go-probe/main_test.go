package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRejectsOversizedRequest(t *testing.T) {
	input := strings.Repeat(" ", maxRecordBytes+1)
	if err := run(strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("oversized request passed")
	}
}

func TestRejectsUnknownField(t *testing.T) {
	input := `{"schema_version":1,"unknown":true}`
	if err := run(strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("unknown request field passed")
	}
}
