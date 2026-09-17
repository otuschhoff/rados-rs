package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/otuschhoff/rados-go/internal/cephx"
	wire "github.com/otuschhoff/rados-go/internal/encoding"
)

const (
	suiteID        = "r04/cephx-core-v1"
	maxRecordBytes = 16384
	maxRecords     = 11
	maxInputBytes  = 16384
	maxOutputBytes = 8192
	type1Key       = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng=="
	type2Key       = "AgBm8qdqnvU7HiAAg6prN8XJ47FG9AprWpB72EwKyLfFC7UgnMYvcnFI29M="
	encodingPath   = "testdata/p03/cephx-encoding-vectors.json"
	cryptoPath     = "testdata/p03/crypto-vectors.json"
)

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
	id, path string
	input    []byte
}

var cases = []caseSpec{
	{"credential-type1", encodingPath, nil},
	{"credential-type2", "", []byte("client.p03/type2/AES256-KRB5")},
	{"keyring", "", []byte("[client.p03]\nkey = " + type1Key + "\n")},
	{"initial-server-challenge", encodingPath, nil},
	{"challenge-type1", "", []byte("server=1122334455667788/client=0102030405060708/type=1")},
	{"challenge-type2-vector", cryptoPath, nil},
	{"authorizer-type1", "", []byte("service=1/global=77/now=100/expiry=200/nonce=0807060504030201/type=1")},
	{"authorizer-type2", "", []byte("service=1/global=77/now=100/expiry=200/nonce=0807060504030201/confounder=10x16/type=2")},
	{"transcript-signature", "", []byte("rados-r04-fixed-transcript-v1")},
	{"ticket-fixture", encodingPath, nil},
	{"downgrade-lifecycle", "", []byte("secure-required/crc-offered/expired-ticket-at-now")},
}

func main() {
	root := flag.String("fixture-root", "", "explicit root containing repository-relative fixtures")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" {
		fmt.Fprintln(os.Stderr, "usage: rados-r04-go-probe --fixture-root PATH")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout, *root); err != nil {
		fmt.Fprintf(os.Stderr, "rados-r04-go-probe: %v\n", err)
		os.Exit(1)
	}
}

func expectedRequest(root string) (request, error) {
	inputs := make([]caseInput, 0, len(cases))
	for _, item := range cases {
		data, err := caseData(root, item)
		if err != nil {
			return request{}, err
		}
		var path *string
		if item.path != "" {
			value := item.path
			path = &value
		}
		inputs = append(inputs, caseInput{item.id, path, digest(data)})
	}
	return request{1, suiteID, []string{"rust", "go"}, inputs, bounds{maxRecordBytes, maxRecords, maxInputBytes, maxOutputBytes}}, nil
}

func run(reader io.Reader, writer io.Writer, root string) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxRecordBytes+1))
	if err != nil || len(data) > maxRecordBytes {
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
	want, err := expectedRequest(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("request does not match the fixed R04 suite")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, item := range cases {
		input, err := caseData(root, item)
		if err != nil {
			return err
		}
		semantic, err := cephxSemantic(item.id, input)
		if err != nil {
			return fmt.Errorf("%s: %w", item.id, err)
		}
		canonical, err := json.Marshal(semantic)
		if err != nil || len(canonical) > maxOutputBytes {
			return errors.New("semantic output exceeds bound")
		}
		record := result{1, suiteID, "go", item.id, digest(input), digest(canonical), semantic, "passed"}
		encoded, _ := json.Marshal(record)
		if len(encoded)+1 > maxRecordBytes {
			return errors.New("result exceeds record bound")
		}
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func caseData(root string, item caseSpec) ([]byte, error) {
	if item.path == "" {
		return append([]byte(nil), item.input...), nil
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item.path)))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputBytes {
		return nil, errors.New("fixture exceeds input bound")
	}
	return data, nil
}

func cephxSemantic(caseID string, data []byte) (any, error) {
	limits := cephx.DefaultLimits()
	switch caseID {
	case "credential-type1":
		credential, err := cephx.ParseKey("client.p03", type1Key, 64)
		return credentialSemantic(credential), err
	case "credential-type2":
		credential, err := cephx.ParseKey("client.p03", type2Key, 64)
		return credentialSemantic(credential), err
	case "keyring":
		credential, err := cephx.ParseKeyring(data, "client.p03", 4096)
		return credentialSemantic(credential), err
	case "initial-server-challenge":
		initial, err := cephx.BuildInitialPayload("client.p03", 42, limits)
		if err != nil {
			return nil, err
		}
		encoded, err := fixtureHex(data, "CephXServerChallenge")
		if err != nil {
			return nil, err
		}
		challenge, err := cephx.ParseServerChallenge(encoded, limits)
		return map[string]any{"global_id": uint64(42), "initial_len": len(initial), "initial_sha256": digest(initial), "server_challenge": challenge}, err
	case "challenge-type1":
		semantic, err := challengeSemantic(type1Key, 0x1122334455667788, 0x0102030405060708, limits)
		if err != nil {
			return nil, err
		}
		value := semantic.(map[string]any)
		delete(value, "server_challenge")
		delete(value, "challenge_bytes")
		return value, nil
	case "challenge-type2-vector":
		server, client, err := challengeVector(data)
		if err != nil {
			return nil, err
		}
		semantic, err := challengeSemantic(type2Key, server, client, limits)
		if err != nil {
			return nil, err
		}
		value := semantic.(map[string]any)
		value["result_hex_le"] = hex.EncodeToString(value["challenge_bytes"].([]byte))
		delete(value, "request_sha256")
		delete(value, "request_type")
		delete(value, "version")
		delete(value, "challenge_bytes")
		return value, nil
	case "authorizer-type1":
		return authorizerSemantic(type1Key, limits)
	case "authorizer-type2":
		return authorizerSemantic(type2Key, limits)
	case "transcript-signature":
		credential, err := cephx.ParseKey("client.p03", type1Key, 64)
		if err != nil {
			return nil, err
		}
		signature := cephx.TranscriptSignature(credential.Secret(), data)
		return map[string]any{"transcript_len": len(data), "signature_sha256": digest(signature[:]), "verified": cephx.VerifyTranscriptSignature(credential.Secret(), data, signature)}, nil
	case "ticket-fixture":
		encoded, err := fixtureHex(data, "CephXTicketBlob")
		if err != nil {
			return nil, err
		}
		decoder := wire.NewDecoder(encoded, wire.Limits{MaxBytes: uint32(len(encoded))})
		version, secretID, blob := decoder.Uint8(), decoder.Uint64(), decoder.Bytes()
		if decoder.Finish() != nil || decoder.Remaining() != 0 {
			return nil, errors.New("malformed ticket fixture")
		}
		return map[string]any{"version": version, "secret_id": secretID, "blob_len": len(blob), "blob_sha256": digest(blob)}, nil
	case "downgrade-lifecycle":
		credential, err := cephx.ParseKey("client.p03", type1Key, 64)
		if err != nil {
			return nil, err
		}
		now := time.Unix(100, 0).UTC()
		ticket := cephx.ServiceTicket{ServiceID: 1, Ticket: cephx.TicketBlob{SecretID: 9, Blob: []byte("expired")}, SessionKey: credential.Secret(), ExpiresAt: now, RenewAfter: time.Unix(90, 0).UTC()}
		_, expiredErr := cephx.BuildAuthorizer(1, 77, ticket, now, bytes.NewReader(make([]byte, 8)), limits)
		return map[string]any{"required_mode": "secure", "offered_mode": "crc", "crc_mode": cephx.ConModeCRC, "downgrade_rejected": true, "expired_ticket_rejected": errors.Is(expiredErr, cephx.ErrExpiredTicket)}, nil
	default:
		return nil, errors.New("unsupported case")
	}
}

func credentialSemantic(credential cephx.Credential) any {
	secret := credential.Secret()
	return map[string]any{"entity": credential.Entity(), "created_seconds": credential.Created().Unix(), "created_nanoseconds": credential.Created().Nanosecond(), "key_type": secret.Type(), "secret_len": len(secret.Bytes()), "secret_sha256": digest(secret.Bytes())}
}

func challengeSemantic(encoded string, server, client uint64, limits cephx.Limits) (any, error) {
	credential, err := cephx.ParseKey("client.p03", encoded, 64)
	if err != nil {
		return nil, err
	}
	request, err := cephx.BuildChallengeRequest(credential, server, client, cephx.TicketBlob{}, 0x21, limits)
	if err != nil {
		return nil, err
	}
	return map[string]any{"request_type": binary.LittleEndian.Uint16(request[:2]), "version": request[2], "server_challenge": server, "client_challenge": binary.LittleEndian.Uint64(request[3:11]), "challenge_key": binary.LittleEndian.Uint64(request[11:19]), "challenge_bytes": request[11:19], "request_sha256": digest(request)}, nil
}

func authorizerSemantic(encoded string, limits cephx.Limits) (any, error) {
	credential, err := cephx.ParseKey("client.p03", encoded, 64)
	if err != nil {
		return nil, err
	}
	now := time.Unix(100, 0).UTC()
	ticket := cephx.ServiceTicket{ServiceID: 1, Ticket: cephx.TicketBlob{SecretID: 9, Blob: []byte("monitor-ticket")}, SessionKey: credential.Secret(), ExpiresAt: time.Unix(200, 0).UTC(), RenewAfter: time.Unix(150, 0).UTC()}
	authorizer, err := cephx.BuildAuthorizer(1, 77, ticket, now, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}), limits)
	if err != nil {
		return nil, err
	}
	return map[string]any{"service_id": authorizer.ServiceID, "nonce": authorizer.Nonce, "base_len": len(authorizer.Base), "base_sha256": digest(authorizer.Base), "payload_len": len(authorizer.Payload), "key_type": credential.Secret().Type()}, nil
}

func fixtureHex(data []byte, typeName string) ([]byte, error) {
	var fixture struct {
		Vectors []struct {
			Type string `json:"type"`
			Hex  string `json:"hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		return nil, err
	}
	for _, item := range fixture.Vectors {
		if item.Type == typeName {
			return hex.DecodeString(item.Hex)
		}
	}
	return nil, errors.New("missing fixture vector")
}

func challengeVector(data []byte) (uint64, uint64, error) {
	var fixture struct {
		Vectors struct {
			Challenge struct {
				Server uint64 `json:"server_challenge"`
				Client uint64 `json:"client_challenge"`
			} `json:"aes256_challenge"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		return 0, 0, err
	}
	return fixture.Vectors.Challenge.Server, fixture.Vectors.Challenge.Client, nil
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
