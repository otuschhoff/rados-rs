package main

import (
	"bufio"
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
	"strconv"
	"strings"

	"github.com/otuschhoff/rados-go/internal/crush"
	"github.com/otuschhoff/rados-go/internal/maps"
)

const suiteID = "r06/placement-v1"
const maxRecordBytes = 16384
const maxInputBytes = 1 << 20
const maxOutputBytes = 4096

type bounds struct {
	MaxRecordBytes uint64 `json:"max_record_bytes"`
	MaxRecords     int    `json:"max_records"`
	MaxInputBytes  uint64 `json:"max_input_bytes"`
	MaxOutputBytes uint64 `json:"max_output_bytes"`
	MaxSeconds     uint64 `json:"max_seconds"`
}
type caseInput struct {
	CaseID string `json:"case_id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
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
	id, path, corpus string
	rule             uint32
	pgCount          uint32
	weights          []uint32
	object, upmap, erasureObject, primaryAffinity bool
}

var cases = []caseSpec{
	{"p05-direct-baseline", "testdata/r06/p05/mappings.txt", "p05", 0, 0, []uint32{0x10000, 0x10000, 0x10000, 0x10000}, false, false, false, false},
	{"p05-direct-osd1-out", "testdata/r06/p05/mappings-osd1-out.txt", "p05", 0, 0, []uint32{0x10000, 0, 0x10000, 0x10000}, false, false, false, false},
	{"p05-object-baseline", "testdata/r06/p05/object-mappings.txt", "p05", 0, 256, []uint32{0x10000, 0x10000, 0x10000, 0x10000}, true, false, false, false},
	{"p05-object-pg32", "testdata/r06/p05/object-mappings-pg32.txt", "p05", 0, 32, []uint32{0x10000, 0x10000, 0x10000, 0x10000}, true, false, false, false},
	{"p05-object-osd1-out", "testdata/r06/p05/object-mappings-osd1-out.txt", "p05", 0, 32, []uint32{0x10000, 0, 0x10000, 0x10000}, true, false, false, false},
	{"p05-object-upmap", "testdata/r06/p05/object-mappings-upmap.txt", "p05", 0, 256, []uint32{0x10000, 0x10000, 0x10000, 0x10000}, true, true, false, false},
	{"p10-erasure-baseline", "testdata/r06/p10/mappings.txt", "p10", 2, 0, []uint32{0x10000, 0x10000, 0x10000}, false, false, false, false},
	{"p10-erasure-osd1-out", "testdata/r06/p10/mappings-osd1-out.txt", "p10", 2, 0, []uint32{0x10000, 0, 0x10000}, false, false, false, false},
	{"p10-erasure-object-baseline", "testdata/r06/p10/object-placements.jsonl", "p10", 2, 16, []uint32{0x10000, 0x10000, 0x10000}, false, false, true, false},
	{"p10-erasure-object-osd1-out", "testdata/r06/p10/object-placements-osd1-out.jsonl", "p10", 2, 16, []uint32{0x10000, 0, 0x10000}, false, false, true, false},
	{"p10-erasure-object-primary-affinity", "testdata/r06/p10/object-placements-primary-affinity.jsonl", "p10", 2, 16, []uint32{0x10000, 0x10000, 0x10000}, false, false, true, true},
}

func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }
func readBounded(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputBytes {
		return nil, errors.New("input exceeds bound")
	}
	return data, nil
}
func canonical(value any, output *bytes.Buffer) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	output.Write(data)
	output.WriteByte('\n')
	return nil
}
func parseOSDs(encoded string) ([]int32, error) {
	encoded = strings.TrimSuffix(strings.TrimPrefix(encoded, "["), "]")
	fields := strings.Split(encoded, ",")
	result := make([]int32, 0, len(fields))
	for _, field := range fields {
		value, err := strconv.ParseInt(field, 10, 32)
		if err != nil {
			return nil, err
		}
		result = append(result, int32(value))
	}
	return result, nil
}

func readUpmap(root string) (map[maps.PG][]maps.OSDRemap, error) {
	file, err := os.Open(filepath.Join(root, "testdata/r06/p05/upmap-commands.txt"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make(map[maps.PG][]maps.OSDRemap)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var seedHex string
		var from, to int32
		if _, err := fmt.Sscanf(scanner.Text(), "ceph osd pg-upmap-items 1.%s %d %d", &seedHex, &from, &to); err != nil {
			return nil, err
		}
		seed, err := strconv.ParseUint(seedHex, 16, 32)
		if err != nil {
			return nil, err
		}
		pg := maps.PG{Pool: 1, Seed: uint32(seed), Preferred: -1}
		result[pg] = append(result[pg], maps.OSDRemap{From: from, To: to})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) != 20 {
		return nil, errors.New("upmap command count is not 20")
	}
	return result, nil
}

func directSemantic(root string, item caseSpec) (any, error) {
	mapData, err := readBounded(filepath.Join(root, "testdata/r06", item.corpus, "crushmap.bin"))
	if err != nil {
		return nil, err
	}
	crushMap, err := crush.DecodeMap(mapData, crush.DecodeLimits{MaxBytes: 1 << 20, MaxBuckets: 1024, MaxRules: 256, MaxItems: 65536, MaxNames: 65536})
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(root, item.path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	prefix := fmt.Sprintf("CRUSH rule %d x ", item.rule)
	var actual, native bytes.Buffer
	rows := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		row := strings.TrimPrefix(scanner.Text(), prefix)
		if row == scanner.Text() {
			return nil, errors.New("invalid direct row")
		}
		fields := strings.SplitN(row, " ", 2)
		if len(fields) != 2 {
			return nil, errors.New("incomplete direct row")
		}
		seed, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return nil, err
		}
		expected, err := parseOSDs(fields[1])
		if err != nil {
			return nil, err
		}
		osds, err := crushMap.Place(item.rule, uint32(seed), 3, item.weights)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(osds, expected) {
			return nil, fmt.Errorf("native CRUSH mismatch for seed %d", seed)
		}
		value := map[string]any{"osds": osds, "rule": item.rule, "seed": uint32(seed)}
		if err := canonical(value, &actual); err != nil {
			return nil, err
		}
		value["osds"] = expected
		if err := canonical(value, &native); err != nil {
			return nil, err
		}
		rows++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if rows != 256 {
		return nil, fmt.Errorf("rows=%d", rows)
	}
	return map[string]any{"kind": "direct", "row_count": rows, "normalized_sha256": digest(actual.Bytes()), "native_normalized_sha256": digest(native.Bytes())}, nil
}

func objectSemantic(root string, item caseSpec) (any, error) {
	mapData, err := readBounded(filepath.Join(root, "testdata/r06/p05/crushmap.bin"))
	if err != nil {
		return nil, err
	}
	remaps := map[maps.PG][]maps.OSDRemap{}
	if item.upmap {
		remaps, err = readUpmap(root)
		if err != nil {
			return nil, err
		}
	}
	osdMap := maps.R06ObjectMap(mapData, item.pgCount, item.weights, remaps)
	file, err := os.Open(filepath.Join(root, item.path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var actual, native bytes.Buffer
	rows := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		row := strings.TrimPrefix(scanner.Text(), "object '")
		if row == scanner.Text() {
			return nil, errors.New("invalid object row")
		}
		identity := strings.SplitN(row, "' -> 1.", 2)
		if len(identity) != 2 {
			return nil, errors.New("invalid object identity")
		}
		fields := strings.SplitN(identity[1], " -> ", 2)
		if len(fields) != 2 {
			return nil, errors.New("incomplete object row")
		}
		pg, err := strconv.ParseUint(fields[0], 16, 32)
		if err != nil {
			return nil, err
		}
		osds, err := parseOSDs(fields[1])
		if err != nil {
			return nil, err
		}
		placement, err := osdMap.PlaceObject(1, identity[0], "", "")
		if err != nil {
			return nil, err
		}
		if len(osds) == 0 || placement.PG.Seed != uint32(pg) || !reflect.DeepEqual(placement.Up, osds) || !reflect.DeepEqual(placement.Acting, osds) || placement.UpPrimary != osds[0] || placement.ActingPrimary != osds[0] || (!item.upmap && !reflect.DeepEqual(placement.Raw, osds)) {
			return nil, fmt.Errorf("native object mismatch for %s", identity[0])
		}
		if err := canonical(map[string]any{"acting": placement.Acting, "acting_primary": placement.ActingPrimary, "object": identity[0], "pg": placement.PG.Seed, "placement_seed": placement.PlacementSeed, "primary_shard": placement.PrimaryShard, "raw": placement.Raw, "raw_hash": placement.RawHash, "raw_pg": placement.RawPG.Seed, "sharded": placement.Sharded, "up": placement.Up, "up_primary": placement.UpPrimary}, &actual); err != nil {
			return nil, err
		}
		if err := canonical(map[string]any{"object": identity[0], "osds": osds, "pg": uint32(pg)}, &native); err != nil {
			return nil, err
		}
		rows++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if rows != 128 {
		return nil, fmt.Errorf("rows=%d", rows)
	}
	return map[string]any{"kind": "object", "row_count": rows, "normalized_sha256": digest(actual.Bytes()), "native_normalized_sha256": digest(native.Bytes())}, nil
}

type nativeObjectPlacement struct {
	Object        string  `json:"object"`
	RawPGID       string  `json:"raw_pgid"`
	PGID          string  `json:"pgid"`
	Up            []int32 `json:"up"`
	UpPrimary     int32   `json:"up_primary"`
	Acting        []int32 `json:"acting"`
	ActingPrimary int32   `json:"acting_primary"`
}

func pgSeed(value string) (uint32, error) {
	fields := strings.SplitN(value, ".", 2)
	if len(fields) != 2 {
		return 0, errors.New("invalid PG")
	}
	seed, err := strconv.ParseUint(fields[1], 16, 32)
	return uint32(seed), err
}

func erasureObjectSemantic(root string, item caseSpec) (any, error) {
	mapData, err := readBounded(filepath.Join(root, "testdata/r06/p10/crushmap.bin"))
	if err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(root, item.path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var actual, native bytes.Buffer
	rows := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var expected nativeObjectPlacement
		if err := json.Unmarshal(scanner.Bytes(), &expected); err != nil {
			return nil, err
		}
		rawHash, err := pgSeed(expected.RawPGID)
		if err != nil {
			return nil, err
		}
		seed, err := pgSeed(expected.PGID)
		if err != nil {
			return nil, err
		}
		pg := maps.PG{Pool: 3, Seed: seed, Preferred: -1}
		pgTemp := map[maps.PG][]int32{}
		primaryTemp := map[maps.PG]int32{}
		if !reflect.DeepEqual(expected.Acting, expected.Up) {
			pgTemp[pg] = expected.Acting
		}
		if expected.ActingPrimary != expected.UpPrimary {
			primaryTemp[pg] = expected.ActingPrimary
		}
		affinity := []uint32(nil)
		if item.primaryAffinity {
			affinity = []uint32{0, 0x10000, 0x10000}
		}
		osdMap := maps.R06ErasureMap(mapData, item.weights, affinity, pgTemp, primaryTemp)
		placement, err := osdMap.PlaceObject(3, expected.Object, "", "")
		if err != nil {
			return nil, err
		}
		primaryShard := int8(-1)
		for index, osd := range expected.Acting {
			if osd == expected.ActingPrimary {
				primaryShard = int8(index)
				break
			}
		}
		if placement.RawHash != rawHash || placement.RawPG.Seed != rawHash || placement.PG.Seed != seed || !reflect.DeepEqual(placement.Raw, expected.Up) || !reflect.DeepEqual(placement.Up, expected.Up) || placement.UpPrimary != expected.UpPrimary || !reflect.DeepEqual(placement.Acting, expected.Acting) || placement.ActingPrimary != expected.ActingPrimary || placement.PrimaryShard != primaryShard || !placement.Sharded {
			return nil, fmt.Errorf("native erasure object mismatch for %s", expected.Object)
		}
		if err := canonical(map[string]any{"acting": placement.Acting, "acting_primary": placement.ActingPrimary, "object": expected.Object, "pg": placement.PG.Seed, "placement_seed": placement.PlacementSeed, "primary_shard": placement.PrimaryShard, "raw": placement.Raw, "raw_hash": placement.RawHash, "raw_pg": placement.RawPG.Seed, "sharded": placement.Sharded, "up": placement.Up, "up_primary": placement.UpPrimary}, &actual); err != nil {
			return nil, err
		}
		if err := canonical(map[string]any{"acting": expected.Acting, "acting_primary": expected.ActingPrimary, "object": expected.Object, "pg": seed, "primary_shard": primaryShard, "raw_hash": rawHash, "up": expected.Up, "up_primary": expected.UpPrimary}, &native); err != nil {
			return nil, err
		}
		rows++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if rows != 128 {
		return nil, fmt.Errorf("rows=%d", rows)
	}
	return map[string]any{"kind": "object", "row_count": rows, "normalized_sha256": digest(actual.Bytes()), "native_normalized_sha256": digest(native.Bytes())}, nil
}

func expectedRequest(root string) (request, error) {
	inputs := make([]caseInput, 0, len(cases))
	for _, item := range cases {
		data, err := readBounded(filepath.Join(root, item.path))
		if err != nil {
			return request{}, err
		}
		inputs = append(inputs, caseInput{item.id, item.path, digest(data)})
	}
	return request{1, suiteID, []string{"rust", "go"}, inputs, bounds{maxRecordBytes, len(cases), maxInputBytes, maxOutputBytes, 30}}, nil
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
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	want, err := expectedRequest(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("request does not match fixed R06 suite")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, item := range cases {
		input, err := readBounded(filepath.Join(root, item.path))
		if err != nil {
			return err
		}
		var semantic any
		if item.erasureObject {
			semantic, err = erasureObjectSemantic(root, item)
		} else if item.object {
			semantic, err = objectSemantic(root, item)
		} else {
			semantic, err = directSemantic(root, item)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", item.id, err)
		}
		canonicalValue, err := json.Marshal(semantic)
		if err != nil || len(canonicalValue) > maxOutputBytes {
			return errors.New("semantic exceeds bound")
		}
		record := result{1, suiteID, "go", item.id, digest(input), digest(canonicalValue), semantic, "passed"}
		encoded, _ := json.Marshal(record)
		if len(encoded)+1 > maxRecordBytes {
			return errors.New("result exceeds bound")
		}
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	root := flag.String("fixture-root", "", "repository fixture root")
	flag.Parse()
	if *root == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: rados-r06-go-probe --fixture-root PATH")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout, *root); err != nil {
		fmt.Fprintf(os.Stderr, "rados-r06-go-probe: %v\n", err)
		os.Exit(1)
	}
}
