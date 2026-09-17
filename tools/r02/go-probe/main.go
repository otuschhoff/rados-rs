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

	wire "github.com/otuschhoff/rados-go/internal/encoding"
)

const (
	caseID         = "r02/versioned-envelope-newer-compatible"
	operation      = "versioned-envelope-round-trip"
	inputBase64    = "AwEDAAAAAQL/"
	inputSHA256    = "ddf6a266b64aecd343a549cf7f07562e2622236ec8cef93133a1b00372361edb"
	maxRecordBytes = 4096
	inputBytes     = 9
	localVersion   = 2
	structCompat   = 1
)

type request struct {
	SchemaVersion uint32     `json:"schema_version"`
	CaseID        string     `json:"case_id"`
	Operation     string     `json:"operation"`
	LocalVersion  uint8      `json:"local_version"`
	Input         probeInput `json:"input"`
	Limits        limits     `json:"limits"`
}

type probeInput struct {
	EncodedBase64 string `json:"encoded_base64"`
	SHA256        string `json:"sha256"`
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
	InputSHA256    string `json:"input_sha256"`
	Fields         fields `json:"fields"`
	EncodedBase64  string `json:"encoded_base64"`
	EncodedSHA256  string `json:"encoded_sha256"`
	Status         string `json:"status"`
}

type fields struct {
	LocalVersion   uint8  `json:"local_version"`
	StructVersion  uint8  `json:"struct_version"`
	StructCompat   uint8  `json:"struct_compat"`
	KnownValue     uint16 `json:"known_value"`
	TrailingBase64 string `json:"trailing_base64"`
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "rados-r02-go-probe: %v\n", err)
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
	decoderJSON := json.NewDecoder(bytes.NewReader(requestData))
	decoderJSON.DisallowUnknownFields()
	var requestValue request
	if err := decoderJSON.Decode(&requestValue); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	var trailingJSON any
	if err := decoderJSON.Decode(&trailingJSON); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	if requestValue.SchemaVersion != 1 || requestValue.CaseID != caseID || requestValue.Operation != operation || requestValue.LocalVersion != localVersion || requestValue.Input.EncodedBase64 != inputBase64 || requestValue.Input.SHA256 != inputSHA256 {
		return errors.New("request identity does not match the supported R02 case")
	}
	if requestValue.Limits.MaxRecordBytes != maxRecordBytes || requestValue.Limits.MaxInputBytes != inputBytes || requestValue.Limits.MaxOutputBytes != inputBytes {
		return errors.New("request limits do not match the supported R02 bounds")
	}
	data, err := base64.StdEncoding.DecodeString(requestValue.Input.EncodedBase64)
	if err != nil || len(data) != inputBytes {
		return errors.New("input bytes do not match the fixed R02 case")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != inputSHA256 {
		return errors.New("input hash does not match the fixed R02 case")
	}

	decoderWire := wire.NewDecoder(data, wire.Limits{MaxBytes: inputBytes})
	version, payload := decoderWire.Versioned(localVersion)
	knownValue := payload.Uint16()
	unknown := payload.Raw(uint32(payload.Remaining()))
	if err := payload.Finish(); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	if decoderWire.Remaining() != 0 {
		return errors.New("bytes remain after the versioned envelope")
	}
	if err := decoderWire.Finish(); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}

	encoder := wire.NewEncoder(inputBytes)
	encoder.Versioned(version, structCompat, func(payload *wire.Encoder) {
		payload.Uint16(knownValue)
		payload.Raw(unknown)
	})
	reencoded, err := encoder.BytesResult()
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}
	if !bytes.Equal(reencoded, data) {
		return errors.New("versioned envelope did not re-encode exactly")
	}
	encodedDigest := sha256.Sum256(reencoded)
	resultData, err := json.Marshal(result{
		SchemaVersion: 1, CaseID: caseID, Implementation: "go", Operation: operation,
		InputSHA256:   inputSHA256,
		Fields:        fields{LocalVersion: localVersion, StructVersion: version, StructCompat: structCompat, KnownValue: knownValue, TrailingBase64: base64.StdEncoding.EncodeToString(unknown)},
		EncodedBase64: base64.StdEncoding.EncodeToString(reencoded), EncodedSHA256: hex.EncodeToString(encodedDigest[:]), Status: "passed",
	})
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	resultData = append(resultData, '\n')
	if len(resultData) > maxRecordBytes {
		return errors.New("probe result exceeds record bound")
	}
	written, err := writer.Write(resultData)
	if err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	if written != len(resultData) {
		return io.ErrShortWrite
	}
	return nil
}
