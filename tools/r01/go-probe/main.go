package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	wire "github.com/otuschhoff/rados-go/internal/encoding"
	"github.com/otuschhoff/rados-go/internal/protocol"
)

const (
	caseID           = "p01/entity-name-client-1"
	operation        = "entity-name-round-trip"
	fixturePath      = "testdata/p01/entity-name-client-1.bin"
	fixtureSHA256    = "0ea9e19802a23c4674e289fabeaa6e600262fb9ad25ae64fd4fb927651b6abe9"
	maxRecordBytes   = 4096
	fixtureByteCount = 9
)

type request struct {
	SchemaVersion uint32  `json:"schema_version"`
	CaseID        string  `json:"case_id"`
	Operation     string  `json:"operation"`
	Fixture       fixture `json:"fixture"`
	Limits        limits  `json:"limits"`
}

type fixture struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type limits struct {
	MaxRecordBytes uint64 `json:"max_record_bytes"`
	MaxInputBytes  uint64 `json:"max_input_bytes"`
	MaxOutputBytes uint64 `json:"max_output_bytes"`
}

type result struct {
	SchemaVersion  uint32 `json:"schema_version"`
	CaseID         string `json:"case_id"`
	Implementation string `json:"implementation_id"`
	Operation      string `json:"operation"`
	FixtureSHA256  string `json:"fixture_sha256"`
	Fields         fields `json:"fields"`
	EncodedBase64  string `json:"encoded_base64"`
	EncodedSHA256  string `json:"encoded_sha256"`
	Status         string `json:"status"`
}

type fields struct {
	EntityType uint8  `json:"entity_type"`
	Number     string `json:"number"`
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "rados-r01-go-probe: %v\n", err)
		os.Exit(1)
	}
}

func run(reader io.Reader, writer io.Writer) error {
	requestData, err := io.ReadAll(io.LimitReader(reader, maxRecordBytes+1))
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if len(requestData) > maxRecordBytes {
		return fmt.Errorf("request exceeds %d bytes", maxRecordBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(requestData))
	decoder.DisallowUnknownFields()
	var requestValue request
	if err := decoder.Decode(&requestValue); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	if requestValue.SchemaVersion != 1 || requestValue.CaseID != caseID || requestValue.Operation != operation || requestValue.Fixture.Path != fixturePath || requestValue.Fixture.SHA256 != fixtureSHA256 {
		return errors.New("request identity does not match the supported R01 case")
	}
	if requestValue.Limits.MaxRecordBytes != maxRecordBytes || requestValue.Limits.MaxInputBytes != fixtureByteCount || requestValue.Limits.MaxOutputBytes != fixtureByteCount {
		return errors.New("request limits do not match the supported R01 bounds")
	}
	info, err := os.Stat(filepath.Clean(fixturePath))
	if err != nil {
		return fmt.Errorf("read fixture metadata: %w", err)
	}
	if info.Size() != fixtureByteCount {
		return fmt.Errorf("fixture contains %d bytes, expected %d", info.Size(), fixtureByteCount)
	}
	fixtureData, err := os.ReadFile(filepath.Clean(fixturePath))
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}
	digest := sha256.Sum256(fixtureData)
	if hex.EncodeToString(digest[:]) != fixtureSHA256 {
		return errors.New("fixture hash does not match the pinned R01 value")
	}
	decoderWire := wire.NewDecoder(fixtureData, wire.Limits{MaxBytes: fixtureByteCount})
	name := protocol.DecodeEntityName(decoderWire)
	if err := decoderWire.Finish(); err != nil {
		return fmt.Errorf("decode entity name: %w", err)
	}
	encoder := wire.NewEncoder(fixtureByteCount)
	name.Encode(encoder)
	encoded, err := encoder.BytesResult()
	if err != nil {
		return fmt.Errorf("encode entity name: %w", err)
	}
	encodedDigest := sha256.Sum256(encoded)
	resultValue := result{
		SchemaVersion:  1,
		CaseID:         caseID,
		Implementation: "go",
		Operation:      operation,
		FixtureSHA256:  fixtureSHA256,
		Fields:         fields{EntityType: uint8(name.Type), Number: strconv.FormatInt(name.Num, 10)},
		EncodedBase64:  base64.StdEncoding.EncodeToString(encoded),
		EncodedSHA256:  hex.EncodeToString(encodedDigest[:]),
		Status:         "passed",
	}
	return json.NewEncoder(writer).Encode(resultValue)
}
