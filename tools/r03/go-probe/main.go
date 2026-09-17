package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/otuschhoff/rados-go/internal/msgr"
)

const (
	suiteID        = "r03/messenger-transcript-v1"
	maxRecordBytes = 16384
	maxRecords     = 6
	maxInputBytes  = 4096
	maxOutputBytes = 8192
)

var limits = msgr.Limits{MaxSegmentBytes: 4096, MaxFrameBytes: 8192, MaxAddresses: 4, MaxAuthBytes: 4096}
var sessionScript = []byte("start-ready\nstop\n")

type bounds struct {
	MaxRecordBytes uint64 `json:"max_record_bytes"`
	MaxRecords     int    `json:"max_records"`
	MaxInputBytes  uint64 `json:"max_input_bytes"`
	MaxOutputBytes uint64 `json:"max_output_bytes"`
}

type caseInput struct {
	CaseID string  `json:"case_id"`
	Path   *string `json:"path"`
	SHA256 string  `json:"sha256"`
}

type request struct {
	SchemaVersion     uint32      `json:"schema_version"`
	SuiteID           string      `json:"suite_id"`
	ImplementationIDs []string    `json:"implementation_ids"`
	Cases             []caseInput `json:"cases"`
	Bounds            bounds      `json:"bounds"`
}

type result struct {
	SchemaVersion    uint32 `json:"schema_version"`
	SuiteID          string `json:"suite_id"`
	ImplementationID string `json:"implementation_id"`
	CaseID           string `json:"case_id"`
	InputSHA256      string `json:"input_sha256"`
	OutputSHA256     string `json:"output_sha256"`
	Semantic         any    `json:"semantic"`
	Status           string `json:"status"`
}

type caseSpec struct {
	id, path, sha256 string
}

var cases = []caseSpec{
	{"banner", "testdata/p02/banner-rev1.bin", "6819c56d3d3d3ccaa0545a80d55aaa8088d88e9f849113cdafa58feb298cfcca"},
	{"crc-frame", "testdata/p02/upstream/upstream-crc-four-segment.bin", "0fa63a785151214c426f128141faf3969eb0be008b9229505ab7146401dd8c42"},
	{"secure-frame", "testdata/p02/upstream/upstream-secure-one-segment.bin", "592152e22495cecb210cf5a7bfefac49f6cdd8bbbb14e223db3538bef0b3926d"},
	{"control-ack", "testdata/p02/upstream/upstream-ack-control.bin", "2496a22ad0abda5947019dcdbd5dfe482eab124a649d302cba119df923a6ce70"},
	{"message-frame", "testdata/p02/upstream/upstream-message-frame.bin", "00a22987b019e085cf811b10852000116e3c63adc33bf86729485a2ecb81ff26"},
	{"session-transition", "", ""},
}

func main() {
	fixtureRoot := flag.String("fixture-root", "", "explicit root containing repository-relative fixtures")
	flag.Parse()
	if flag.NArg() != 0 || *fixtureRoot == "" {
		fmt.Fprintln(os.Stderr, "usage: rados-r03-go-probe --fixture-root PATH")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout, *fixtureRoot); err != nil {
		fmt.Fprintf(os.Stderr, "rados-r03-go-probe: %v\n", err)
		os.Exit(1)
	}
}

func expectedRequest() request {
	inputs := make([]caseInput, 0, len(cases))
	for _, item := range cases {
		var path *string
		digest := item.sha256
		if item.path != "" {
			value := item.path
			path = &value
		} else {
			digest = digestBytes(sessionScript)
		}
		inputs = append(inputs, caseInput{CaseID: item.id, Path: path, SHA256: digest})
	}
	return request{1, suiteID, []string{"rust", "go"}, inputs, bounds{maxRecordBytes, maxRecords, maxInputBytes, maxOutputBytes}}
}

func run(reader io.Reader, writer io.Writer, fixtureRoot string) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxRecordBytes+1))
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if len(data) > maxRecordBytes {
		return errors.New("request exceeds record bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var got request
	if err := decoder.Decode(&got); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	wantJSON, _ := json.Marshal(expectedRequest())
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(gotJSON, wantJSON) {
		return errors.New("request does not match the fixed R03 suite")
	}
	results, err := goResults(fixtureRoot)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, item := range results {
		encoded, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("encode result: %w", err)
		}
		if len(encoded)+1 > maxRecordBytes {
			return errors.New("result exceeds record bound")
		}
		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("write result: %w", err)
		}
	}
	return nil
}

func goResults(root string) ([]result, error) {
	results := make([]result, 0, maxRecords)
	for _, item := range cases[:5] {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item.path)))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", item.path, err)
		}
		if len(data) > maxInputBytes || digestBytes(data) != item.sha256 {
			return nil, fmt.Errorf("fixture identity is invalid: %s", item.path)
		}
		semantic, err := fixtureSemantic(item.id, data)
		if err != nil {
			return nil, err
		}
		results = append(results, makeResult(item.id, item.sha256, data, semantic))
	}
	semantic, err := sessionSemantic()
	if err != nil {
		return nil, err
	}
	canonical, _ := json.Marshal(semantic)
	results = append(results, makeResult("session-transition", digestBytes(sessionScript), canonical, semantic))
	return results, nil
}

func fixtureSemantic(caseID string, data []byte) (any, error) {
	switch caseID {
	case "banner":
		banner, err := msgr.ReadBanner(bytes.NewReader(data), 16)
		if err != nil || !bytes.Equal(banner.Encode(), data) {
			return nil, errors.New("banner did not round-trip exactly")
		}
		return map[string]any{"supported": banner.Supported, "required": banner.Required}, nil
	case "crc-frame":
		codec := msgr.CRCCodec{WithDataCRC: true}
		frame, err := codec.Read(bytes.NewReader(data), limits)
		if err != nil {
			return nil, err
		}
		encoded, err := codec.Encode(frame, limits)
		if err != nil || !bytes.Equal(encoded, data) {
			return nil, errors.New("CRC frame did not round-trip exactly")
		}
		return frameSemantic(frame), nil
	case "secure-frame":
		secret := make([]byte, 64)
		for index := range secret {
			secret[index] = byte(index)
		}
		decoder, err := msgr.NewSecureCodec(secret, true)
		if err != nil {
			return nil, err
		}
		frame, err := decoder.Read(bytes.NewReader(data), limits)
		if err != nil {
			return nil, err
		}
		encoder, err := msgr.NewSecureCodec(secret, false)
		if err != nil {
			return nil, err
		}
		encoded, err := encoder.Encode(frame, limits)
		if err != nil || !bytes.Equal(encoded, data) {
			return nil, errors.New("secure frame did not round-trip exactly")
		}
		return frameSemantic(frame), nil
	case "control-ack":
		frame, err := msgr.ReadCRC(bytes.NewReader(data), limits)
		if err != nil {
			return nil, err
		}
		payload, err := msgr.DecodeControl(frame, limits)
		ack, ok := payload.(msgr.Ack)
		if err != nil || !ok {
			return nil, errors.New("fixture is not an ACK control")
		}
		return map[string]any{"tag": "ack", "sequence": ack.Sequence}, nil
	case "message-frame":
		frame, err := msgr.ReadCRC(bytes.NewReader(data), limits)
		if err != nil {
			return nil, err
		}
		message, err := msgr.DecodeMessage(frame, limits)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"sequence": message.Header.Sequence, "transaction_id": message.Header.TransactionID,
			"message_type": message.Header.Type, "priority": message.Header.Priority,
			"version": message.Header.Version, "data_pre_padding_length": message.Header.DataPrePaddingLength,
			"data_offset": message.Header.DataOffset, "ack_sequence": message.Header.AckSequence,
			"flags": message.Header.Flags, "compat_version": message.Header.CompatVersion,
			"front_base64":  base64.StdEncoding.EncodeToString(message.Front),
			"middle_base64": base64.StdEncoding.EncodeToString(message.Middle),
			"data_base64":   base64.StdEncoding.EncodeToString(message.Data),
		}, nil
	default:
		return nil, errors.New("unsupported case")
	}
}

func frameSemantic(frame msgr.Frame) any {
	segments := make([]any, 0, len(frame.Segments))
	for _, segment := range frame.Segments {
		segments = append(segments, map[string]any{"alignment": segment.Alignment, "length": len(segment.Data), "sha256": digestBytes(segment.Data)})
	}
	return map[string]any{"tag": frame.Tag, "segments": segments}
}

type fixedSequenceSource struct{}

func (fixedSequenceSource) Next(after uint64) (uint64, error) { return after + 1, nil }

type blockingTransport struct {
	closed chan struct{}
	once   sync.Once
}

func (transport *blockingTransport) ReadFrame() (msgr.Frame, error) {
	<-transport.closed
	return msgr.Frame{}, io.EOF
}
func (*blockingTransport) WriteFrame(msgr.Frame) error { return nil }
func (transport *blockingTransport) Close() error {
	transport.once.Do(func() { close(transport.closed) })
	return nil
}

func sessionSemantic() (any, error) {
	transport := &blockingTransport{closed: make(chan struct{})}
	session, err := msgr.NewSession(transport, nil, msgr.SessionConfig{
		Limits: limits, MaxQueuedMessages: 4, MaxRetainedBytes: 8192,
		MaxInFlightTransactions: 2, MaxReconnectAttempts: 2, MaxHandshakeTransitions: 8,
		ReconnectPolicy: msgr.FailPending, GlobalSequenceSource: fixedSequenceSource{},
	})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	snapshot, err := session.Snapshot(ctx)
	if err != nil || snapshot.State != msgr.StateReady {
		session.Stop()
		return nil, errors.New("session did not reach ready")
	}
	session.Stop()
	select {
	case <-session.Done():
	case <-ctx.Done():
		return nil, errors.New("session did not stop")
	}
	return map[string]any{
		"states":           []string{"disconnected", "ready", "stopped"},
		"ready_accounting": map[string]any{"queued": snapshot.Queued, "in_flight": snapshot.InFlight, "retained_bytes": snapshot.RetainedBytes},
	}, nil
}

func makeResult(caseID, inputSHA string, output []byte, semantic any) result {
	return result{1, suiteID, "go", caseID, inputSHA, digestBytes(output), semantic, "passed"}
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
