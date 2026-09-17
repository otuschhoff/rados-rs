package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFixedEnvelope(t *testing.T) {
	request := `{"schema_version":1,"case_id":"r02/versioned-envelope-newer-compatible","operation":"versioned-envelope-round-trip","local_version":2,"input":{"encoded_base64":"AwEDAAAAAQL/","sha256":"ddf6a266b64aecd343a549cf7f07562e2622236ec8cef93133a1b00372361edb"},"limits":{"max_record_bytes":4096,"max_input_bytes":9,"max_output_bytes":9}}`
	var output bytes.Buffer
	if err := run(strings.NewReader(request), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"struct_version":3`) || !strings.Contains(output.String(), `"trailing_base64":"/w=="`) {
		t.Fatalf("unexpected result: %s", output.String())
	}
}

func TestRejectsOversizedRequest(t *testing.T) {
	if err := run(strings.NewReader(strings.Repeat(" ", maxRecordBytes+1)), &bytes.Buffer{}); err == nil {
		t.Fatal("oversized request passed")
	}
}

func TestRejectsUnknownFieldAndExtraRecord(t *testing.T) {
	if err := run(strings.NewReader(`{"schema_version":1,"unknown":true}`), &bytes.Buffer{}); err == nil {
		t.Fatal("unknown request field passed")
	}
	if err := run(strings.NewReader(`{} {}`), &bytes.Buffer{}); err == nil {
		t.Fatal("multiple JSON values passed")
	}
}
