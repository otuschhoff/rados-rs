package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	rados "github.com/otuschhoff/rados-go"
	"github.com/otuschhoff/rados-go/internal/maps"
)

const (
	suiteID         = "r05/config-maps-v1"
	maxRecordBytes  = 16384
	maxRecords      = 14
	maxInputBytes   = 32 << 20
	maxOutputBytes  = 8192
	monMapPath      = "testdata/p04/monmap-v9.bin"
	osdMapPath      = "testdata/p04/osdmap-v8.bin"
	incrementalPath = "testdata/p04/osdmap-incremental-v8.bin"
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
	{"defaults", "", []byte("Config::default")},
	{"global-entity-precedence", "", []byte("global then exact entity; unknown file option excluded; v1 monitor excluded")},
	{"explicit-env", "", []byte("RADOS_R05 explicit environment prefix")},
	{"args-remainder", "", []byte("recognized args plus unchanged remainder")},
	{"key-over-keyring", "", []byte("direct key wins when both args are present")},
	{"keyring-expansion", "", []byte("$cluster and $name keyring expansion")},
	{"duration-syntax", "", []byte("Go duration units, compound and decimal")},
	{"unknown-retained", "", []byte("unknown programmatic option retained")},
	{"reject-include", "", []byte("file include exclusion")},
	{"reject-duration", "", []byte("non-positive duration rejection")},
	{"reject-monitor-bound", "", []byte("65 monitor seeds exceed bound 64")},
	{"monmap-p04", monMapPath, nil}, {"osdmap-p04", osdMapPath, nil}, {"incremental-p04", incrementalPath, nil},
}

var mapLimits = maps.Limits{MaxBytes: 32 << 20, MaxMonitors: 64, MaxAddresses: 64, MaxLocations: 64, MaxPools: 4096, MaxOSDs: 65536, MaxPGMappings: 1 << 20, MaxCollectionEntries: 1 << 20}

func main() {
	root := flag.String("fixture-root", "", "explicit root containing repository-relative fixtures")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" {
		fmt.Fprintln(os.Stderr, "usage: rados-r05-go-probe --fixture-root PATH")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout, *root); err != nil {
		fmt.Fprintf(os.Stderr, "rados-r05-go-probe: %v\n", err)
		os.Exit(1)
	}
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
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON value")
	}
	want, err := expectedRequest(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("request does not match the fixed R05 suite")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, item := range cases {
		input, err := caseData(root, item)
		if err != nil {
			return err
		}
		semantic, err := semantic(item.id, input, filepath.Join(root, "target/r05/fixtures"))
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

func semantic(id string, data []byte, fixtureRoot string) (any, error) {
	switch id {
	case "monmap-p04":
		value, err := maps.DecodeMonMap(data, mapLimits)
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": "monmap", "fsid": formatFSID(value.FSID()), "epoch": value.Epoch(), "monitor_count": value.MonitorCount(), "ranks": value.Ranks(), "persistent_features": value.PersistentFeatures(), "optional_features": value.OptionalFeatures(), "minimum_monitor_release": value.MinimumMonitorRelease(), "election_strategy": value.ElectionStrategy(), "stretch_mode": value.StretchModeEnabled()}, nil
	case "osdmap-p04":
		value, err := maps.DecodeOSDMap(data, mapLimits)
		if err != nil {
			return nil, err
		}
		poolNames := []string{}
		sort.Strings(poolNames)
		return map[string]any{"kind": "osdmap", "fsid": formatFSID(value.FSID()), "epoch": value.Epoch(), "pool_count": value.PoolCount(), "pools": poolNames, "crc": value.CRC(), "crc_verified": value.CRCVerified(), "sort_bitwise": value.SortBitwise(), "applied_incremental": value.AppliedIncremental()}, nil
	case "incremental-p04":
		value, err := maps.DecodeOSDMapIncremental(data, mapLimits)
		if err != nil {
			return nil, err
		}
		return map[string]any{"kind": "incremental", "fsid": formatFSID(value.FSID()), "epoch": value.Epoch(), "incremental_crc": value.IncrementalCRC(), "full_crc": value.FullCRC()}, nil
	default:
		return configSemantic(id, fixtureRoot)
	}
}

func configSemantic(id, fixtureRoot string) (any, error) {
	config := rados.DefaultConfig()
	remainder := []string{}
	var err error
	switch id {
	case "defaults":
	case "global-entity-precedence":
		config, err = rados.ParseConfig([]byte("[global]\nname = client.r05\nmon host = v1:192.0.2.1:6789, v2:192.0.2.2:3300\noperation timeout = 4s\nfuture option = ignored\n[client.r05]\nmon_host = [v2:192.0.2.3:3300,192.0.2.4:3300]\nms_mode = crc\n"))
	case "explicit-env":
		config, err = config.ParseEnv("RADOS_R05")
	case "args-remainder":
		config, remainder, err = config.ParseArgs([]string{"input", "--unknown", "value", "--id=test", "--mon-host", "v1:192.0.2.9:6789,v2:192.0.2.10:3300", "--operation-timeout=1h2m3.004005006s", "--", "--cluster=ignored"})
	case "key-over-keyring":
		config, remainder, err = config.ParseArgs([]string{"--keyring", filepath.Join(fixtureRoot, "keyring"), "--key", "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng=="})
	case "keyring-expansion":
		config, err = config.WithOption("cluster", "r05")
		if err == nil {
			config, err = config.WithOption("name", "client.r05")
		}
		if err == nil {
			config, err = config.WithOption("keyring", filepath.Join(fixtureRoot, "$cluster.$name.keyring"))
		}
	case "duration-syntax":
		config, err = config.WithOption("dial_timeout", "1h2m3.004005006s")
		if err == nil {
			config, err = config.WithOption("handshake_timeout", "250ms")
		}
		if err == nil {
			config, err = config.WithOption("operation_timeout", "1us")
		}
	case "unknown-retained":
		config, err = config.WithOption("future-option", " enabled ")
	case "reject-include":
		config, err = rados.ParseConfig([]byte("[global]\ninclude = /tmp/ceph.conf\n"))
	case "reject-duration":
		config, err = config.WithOption("operation_timeout", "0s")
	case "reject-monitor-bound":
		config, err = config.WithOption("mon_host", strings.Repeat("v2:192.0.2.1:3300,", 64)+"v2:192.0.2.1:3300")
	default:
		return nil, errors.New("unknown case")
	}
	if err != nil {
		return map[string]any{"status": "error", "kind": "invalid_argument"}, nil
	}
	option := func(name string) any {
		value, ok := config.Option(name)
		if !ok {
			return nil
		}
		return value
	}
	keyHash := any(nil)
	if len(config.Key) != 0 {
		keyHash = digest(config.Key)
	}
	keyring := option("keyring")
	if value, ok := keyring.(string); ok {
		keyring = strings.Replace(value, fixtureRoot, "$fixture", 1)
	}
	mode := "secure"
	if config.SecurityMode == rados.SecurityModeCRC {
		mode = "crc"
	}
	monitors := config.Monitors
	if monitors == nil {
		monitors = []string{}
	}
	return map[string]any{"status": "ok", "cluster": option("cluster"), "entity": config.Entity, "monitors": monitors, "fsid": option("fsid"), "key_sha256": keyHash, "keyring": keyring, "mode": mode, "dial_timeout": option("dial_timeout"), "handshake_timeout": option("handshake_timeout"), "operation_timeout": option("operation_timeout"), "future_option": option("future_option"), "remainder": remainder}, nil
}

func formatFSID(value maps.FSID) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15])
}
func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }
