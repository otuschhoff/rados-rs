// Command p01-verify validates the checked-in P01 module and fixture evidence.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	fixtureDirectory = "testdata/p01"
	ipv6OracleSHA256 = "6dd4fb90dcf8f3e5b2e1380a5b3999a4d4a7ddd81f51c45f2ada5640179abdb4"
	ipv6SeedSHA256   = "a5b18e8166e8aa1d0c3285a6c1a3470851ae2bd229b28da857328c3bd2217986"
)

func expectedFixtures(pins evidencePins) map[string]fixtureExpectation {
	return map[string]fixtureExpectation{
		"entity-name-mon-new.bin": {
			hash:    "1272f520cf7ca5cf117a0b5a3116518371bf20fb7fac043ac1be568b8c55b96c",
			paths:   namePaths,
			command: dencoderCommand(pins.image, "entity_name_t", "1", ""),
		},
		"entity-name-client-1.bin": {
			hash:    "0ea9e19802a23c4674e289fabeaa6e600262fb9ad25ae64fd4fb927651b6abe9",
			paths:   namePaths,
			command: dencoderCommand(pins.image, "entity_name_t", "4", ""),
		},
		"entity-addr-ipv4-legacy.bin": {
			hash:    "3e0124654f5817281cfaa1b056f14b4128b546ef38994d765b6bb09c00868fbf",
			paths:   addressPaths,
			command: dencoderCommand(pins.image, "entity_addr_t", "3", "0"),
		},
		"entity-addr-ipv4-modern.bin": {
			hash:    "43c8ed879a7fd14a2d86ac42f0d78d9ae6d5a785f5e60b6658bcba3b3eb2d7e7",
			paths:   addressPaths,
			command: dencoderCommand(pins.image, "entity_addr_t", "3", "720575940647714820"),
		},
		"entity-addrvec-modern.bin": {
			hash:    "f26c6ce30fe8892264a14b6cd5042549d1eee314f921cf8019faf6be9d5c4345",
			paths:   addressPaths,
			command: dencoderCommand(pins.image, "entity_addrvec_t", "3", "720575940647714820"),
		},
		"entity-addr-ipv6-modern.bin": {
			hash:    "a5b18e8166e8aa1d0c3285a6c1a3470851ae2bd229b28da857328c3bd2217986",
			paths:   addressPaths[:6],
			tool:    "ceph-dencoder",
			version: "20.2.4",
			command: []string{"docker", "run", "--rm", "-v", "$PWD:/src:ro", pins.image, "ceph-dencoder", "type", "entity_addr_t", "import", "/src/integration/p01/entity-addr-ipv6-seed.bin", "decode", "encode", "export", "/dev/stdout"},
		},
	}
}

var (
	namePaths    = []string{"src/include/encoding.h", "src/msg/msg_types.h", "src/tools/ceph-dencoder/common_types.h", "src/tools/ceph-dencoder/ceph_dencoder.cc"}
	addressPaths = []string{"src/include/byteorder.h", "src/include/encoding.h", "src/include/ceph_features.h", "src/include/msgr.h", "src/msg/msg_types.h", "src/msg/msg_types.cc", "src/tools/ceph-dencoder/common_types.h", "src/tools/ceph-dencoder/ceph_dencoder.cc"}
)

type fixtureExpectation struct {
	hash    string
	paths   []string
	tool    string
	version string
	command []string
}

func dencoderCommand(image, typeName, testIndex, features string) []string {
	command := []string{"docker", "run", "--rm", image, "ceph-dencoder", "type", typeName, "select_test", testIndex}
	if features != "" {
		command = append(command, "set_features", features)
	}
	return append(command, "encode", "export", "/dev/stdout")
}

type evidencePins struct {
	repository string
	commit     string
	image      string
	minimumGo  string
}

type manifest struct {
	SchemaVersion int       `json:"schema_version"`
	Fixture       string    `json:"fixture"`
	SHA256        string    `json:"sha256"`
	Kind          string    `json:"kind"`
	Source        source    `json:"source"`
	Generator     generator `json:"generator"`
	Secrets       secrets   `json:"secrets"`
	License       license   `json:"license"`
}

type source struct {
	Repository string   `json:"repository"`
	Commit     string   `json:"commit"`
	Paths      []string `json:"paths"`
}

type generator struct {
	Tool    string   `json:"tool"`
	Version string   `json:"version"`
	Command []string `json:"command"`
	Image   string   `json:"image"`
}

type secrets struct {
	ContainsSecrets bool `json:"contains_secrets"`
	SyntheticOnly   bool `json:"synthetic_only"`
}

type license struct {
	UpstreamExpression string `json:"upstream_expression"`
	Redistribution     string `json:"redistribution"`
	ReviewedBy         string `json:"reviewed_by"`
}

func main() {
	pins := loadEvidence()
	checkModule(pins.minimumGo)
	checkHash("integration/p01/ipv6-fixture.c", ipv6OracleSHA256)
	checkHash("integration/p01/entity-addr-ipv6-seed.bin", ipv6SeedSHA256)
	expected := expectedFixtures(pins)
	entries, err := os.ReadDir(fixtureDirectory)
	must(err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			fatalf("unexpected P01 fixture directory %s", entry.Name())
		}
		names = append(names, entry.Name())
	}
	must(validateArtifactNames(names, expected))
	for name, expectation := range expected {
		checkFixture(name, expectation, pins)
	}
	fmt.Println("P01 verification passed")
}

func validateArtifactNames(names []string, expected map[string]fixtureExpectation) error {
	wantFiles := make(map[string]bool, len(expected)*2)
	for name := range expected {
		wantFiles[name] = true
		wantFiles[name+".json"] = true
	}
	for _, name := range names {
		if !wantFiles[name] {
			return fmt.Errorf("unexpected P01 fixture artifact %s", name)
		}
		delete(wantFiles, name)
	}
	if len(wantFiles) != 0 {
		return fmt.Errorf("missing P01 fixture artifacts: %v", wantFiles)
	}
	return nil
}

func loadEvidence() evidencePins {
	var value struct {
		Ceph struct {
			Repository    string `json:"repository"`
			Qualification struct {
				Commit string `json:"commit"`
			} `json:"qualification_release"`
		} `json:"ceph"`
		Images struct {
			Qualification struct {
				Reference string `json:"reference"`
			} `json:"qualification"`
		} `json:"images"`
		Go struct {
			Minimum struct {
				Version string `json:"version"`
			} `json:"minimum"`
		} `json:"go"`
	}
	data, err := os.ReadFile("docs/p00/evidence.json")
	must(err)
	must(json.Unmarshal(data, &value))
	if value.Ceph.Repository == "" || value.Ceph.Qualification.Commit == "" || value.Images.Qualification.Reference == "" || !strings.HasPrefix(value.Go.Minimum.Version, "go") {
		fatalf("P00 evidence lacks P01 pins")
	}
	return evidencePins{value.Ceph.Repository, value.Ceph.Qualification.Commit, value.Images.Qualification.Reference, strings.TrimPrefix(value.Go.Minimum.Version, "go")}
}

func checkHash(path, want string) {
	data, err := os.ReadFile(path)
	must(err)
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != want {
		fatalf("%s hash is %s, want %s", path, got, want)
	}
}

func checkModule(minimumGo string) {
	data, err := os.ReadFile("go.mod")
	must(err)
	if err := validateModule(data, minimumGo); err != nil {
		fatalf("go.mod must pin the selected module and minimum Go patch: %v", err)
	}
}

func validateModule(data []byte, minimumGo string) error {
	var modulePath, goVersion string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "module":
			if len(fields) != 2 || modulePath != "" {
				return errors.New("invalid or duplicate module directive")
			}
			modulePath = fields[1]
		case "go":
			if len(fields) != 2 || goVersion != "" {
				return errors.New("invalid or duplicate go directive")
			}
			goVersion = fields[1]
		}
	}
	if modulePath != "github.com/otuschhoff/go-librados" {
		return fmt.Errorf("module is %q", modulePath)
	}
	if goVersion != minimumGo {
		return fmt.Errorf("go version is %q, want %q", goVersion, minimumGo)
	}
	return nil
}

func checkFixture(name string, want fixtureExpectation, pins evidencePins) {
	fixturePath := filepath.Join(fixtureDirectory, name)
	data, err := os.ReadFile(fixturePath)
	must(err)
	digest := sha256.Sum256(data)
	actualHash := hex.EncodeToString(digest[:])
	if actualHash != want.hash {
		fatalf("fixture %s hash is %s, want %s", name, actualHash, want.hash)
	}

	manifestPath := fixturePath + ".json"
	requireManifestFields(manifestPath)
	var value manifest
	decodeStrict(manifestPath, &value)
	if value.SchemaVersion != 1 || value.Fixture != name || value.SHA256 != want.hash || value.Kind != "native-oracle" {
		fatalf("fixture %s identity or hash metadata is invalid", name)
	}
	if value.Source.Repository != pins.repository || value.Source.Commit != pins.commit || !slices.Equal(value.Source.Paths, want.paths) {
		fatalf("fixture %s source provenance is incomplete", name)
	}
	tool, version := want.tool, want.version
	if tool == "" {
		tool, version = "ceph-dencoder", "20.2.4"
	}
	if value.Generator.Tool != tool || value.Generator.Version != version || value.Generator.Image != pins.image || !slices.Equal(value.Generator.Command, want.command) {
		fatalf("fixture %s generator is not pinned", name)
	}
	if value.Secrets.ContainsSecrets || !value.Secrets.SyntheticOnly {
		fatalf("fixture %s is not marked synthetic and secret-free", name)
	}
	if value.License.UpstreamExpression == "" || value.License.Redistribution != "approved" || value.License.ReviewedBy != "Oliver Tuschhoff" {
		fatalf("fixture %s lacks redistribution approval", name)
	}
}

func requireManifestFields(path string) {
	data, err := os.ReadFile(path)
	must(err)
	must(validateManifestDocument(data))
}

func validateManifestDocument(data []byte) error {
	var typed manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&typed); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("manifest contains multiple JSON values")
		}
		return err
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	checks := []struct {
		value map[string]any
		keys  []string
	}{
		{value, []string{"schema_version", "fixture", "sha256", "kind", "source", "generator", "secrets", "license"}},
	}
	for _, nested := range []struct {
		key  string
		keys []string
	}{
		{"source", []string{"repository", "commit", "paths"}},
		{"generator", []string{"tool", "version", "command", "image"}},
		{"secrets", []string{"contains_secrets", "synthetic_only"}},
		{"license", []string{"upstream_expression", "redistribution", "reviewed_by"}},
	} {
		object, err := object(value, nested.key)
		if err != nil {
			return err
		}
		checks = append(checks, struct {
			value map[string]any
			keys  []string
		}{object, nested.keys})
	}
	for _, check := range checks {
		if err := requireKeys(check.value, check.keys...); err != nil {
			return err
		}
	}
	return nil
}

func object(value map[string]any, key string) (map[string]any, error) {
	object, ok := value[key].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("field %s must be an object", key)
	}
	return object, nil
}

func requireKeys(value map[string]any, keys ...string) error {
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return fmt.Errorf("manifest lacks required field %s", key)
		}
	}
	return nil
}

func decodeStrict(path string, value any) {
	data, err := os.ReadFile(path)
	must(err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	must(decoder.Decode(value))
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			fatalf("%s contains multiple JSON values", path)
		}
		fatalf("decode %s: %v", path, err)
	}
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "p01-verify: "+format+"\n", arguments...)
	os.Exit(1)
}
