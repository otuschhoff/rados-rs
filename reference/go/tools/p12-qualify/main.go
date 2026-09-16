// Command p12-qualify executes and records the non-live P12 qualification matrix.
package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/otuschhoff/go-librados/internal/p12fuzzevidence"
	"github.com/otuschhoff/go-librados/internal/p12qualcontract"
)

const (
	minimumGo = p12qualcontract.MinimumGo
	latestGo  = p12qualcontract.LatestGo
	module    = p12qualcontract.Module
)

type commandResult struct {
	ID           string `json:"id"`
	Command      string `json:"command"`
	Toolchain    string `json:"toolchain"`
	Platform     string `json:"platform"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	ExitStatus   int    `json:"exit_status"`
	Pass         bool   `json:"pass"`
	OutputSHA256 string `json:"output_sha256"`
	Output       string `json:"output"`
}

type runtimeResult struct {
	commandResult
	Observation *platformObservation `json:"observation"`
}

type platformObservation struct {
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	ModulePath    string `json:"module_path"`
	ModuleVersion string `json:"module_version"`
	CGOEnabled    bool   `json:"cgo_enabled"`
}

type priorReport struct {
	Phase           string            `json:"phase"`
	VerifierCommand string            `json:"verifier_command"`
	CheckID         string            `json:"check_id"`
	Artifacts       map[string]string `json:"artifacts"`
}

type releaseResult struct {
	Version      string              `json:"version"`
	Reproducible bool                `json:"reproducible"`
	Runs         []map[string]string `json:"runs"`
	Artifacts    map[string]string   `json:"artifacts"`
}

type qualificationReport struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Command       string `json:"command"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	Source        struct {
		Identity  string            `json:"identity"`
		Artifacts map[string]string `json:"artifacts"`
	} `json:"source"`
	Checks        []commandResult `json:"checks"`
	RuntimeMatrix []runtimeResult `json:"runtime_matrix"`
	PriorReports  []priorReport   `json:"prior_reports"`
	Release       releaseResult   `json:"release"`
}

type checkSpec = p12qualcontract.Spec

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "docs/p12/qualification-report.json", "qualification report path")
	releaseVersion := flag.String("release-version", "v0.0.0-p12", "release version used for reproducibility evidence")
	checkInventory := flag.String("check-inventory", "", "validate an API inventory and exit")
	flag.Parse()
	if *checkInventory != "" {
		if err := validateInventory(*checkInventory); err != nil {
			fatalf("inventory: %v", err)
		}
		return
	}
	passed, err := qualify(*root, *out, *releaseVersion)
	if err != nil {
		fatalf("qualification: %v", err)
	}
	if !passed {
		os.Exit(1)
	}
}

func qualify(root, output, releaseVersion string) (bool, error) {
	started := time.Now().UTC()
	temporary, err := os.MkdirTemp("", "go-librados-p12-qualification-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(temporary)

	imageAMD64, imageARM64, staticcheck, govulncheck, err := loadPins(root)
	if err != nil {
		return false, err
	}
	pins := p12qualcontract.Pins{ImageAMD64: imageAMD64, ImageARM64: imageARM64, Staticcheck: staticcheck, Govulncheck: govulncheck}
	if pins != p12qualcontract.DefaultPins() {
		return false, errors.New("qualification pins do not match the immutable execution contract")
	}
	releaseOne, releaseTwo := filepath.Join(temporary, "release-1"), filepath.Join(temporary, "release-2")
	specs := p12qualcontract.Checks(pins, releaseVersion)

	var checks []commandResult
	for _, spec := range specs[:len(specs)-10] {
		checks = append(checks, runCommand(root, temporary, spec))
	}

	runtimeSpecs := p12qualcontract.Runtimes(pins)
	var runtimes []runtimeResult
	for _, spec := range runtimeSpecs {
		result := runCommand(root, temporary, spec)
		observation := decodeObservation(result.Output)
		if observation == nil || observation.GOOS+"/"+observation.GOARCH != spec.Platform || observation.ModulePath != module || observation.ModuleVersion == "" || observation.CGOEnabled {
			result.Pass = false
		}
		runtimes = append(runtimes, runtimeResult{commandResult: result, Observation: observation})
	}

	prior := priorBindings(root)
	for _, spec := range specs[len(specs)-10 : len(specs)-1] {
		checks = append(checks, runCommand(root, temporary, spec))
	}

	releaseCheck := runCommand(root, temporary, specs[len(specs)-1])
	checks = append(checks, releaseCheck)
	runs := []map[string]string{hashDirectory(releaseOne), hashDirectory(releaseTwo)}
	reproducible := releaseCheck.Pass && len(runs[0]) == 4 && mapsEqual(runs[0], runs[1])
	if !reproducible {
		checks[len(checks)-1].Pass = false
	}

	source, sourceErr := sourceArtifacts(root)
	if sourceErr != nil {
		return false, sourceErr
	}
	report := qualificationReport{SchemaVersion: 1, Status: "passed", Command: "./integration/p12/qualify.sh", StartedAt: timestamp(started), FinishedAt: timestamp(time.Now().UTC()), Checks: checks, RuntimeMatrix: runtimes, PriorReports: prior, Release: releaseResult{Version: releaseVersion, Reproducible: reproducible, Runs: runs, Artifacts: runs[0]}}
	report.Source.Identity, report.Source.Artifacts = "content-addressed-artifacts", source
	for _, result := range checks {
		if !result.Pass {
			report.Status = "failed"
		}
	}
	for _, result := range runtimes {
		if !result.Pass {
			report.Status = "failed"
		}
	}
	for _, binding := range prior {
		if len(binding.Artifacts) == 0 {
			report.Status = "failed"
		}
	}
	if !reproducible {
		report.Status = "failed"
	}
	if err := writeReport(filepath.Join(root, filepath.FromSlash(output)), report); err != nil {
		return false, err
	}
	return report.Status == "passed", nil
}

func runCommand(root, temporary string, spec checkSpec) commandResult {
	started := time.Now().UTC()
	command := exec.Command("/bin/sh", "-c", spec.Command)
	command.Dir = root
	command.Env = append(os.Environ(), "P12_TMP="+temporary)
	output, err := command.CombinedOutput()
	status := 0
	if err != nil {
		status = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			status = exitErr.ExitCode()
		}
	}
	digest := sha256.Sum256(output)
	passed := err == nil
	if spec.ID == "go-version-latest" && !observedGoVersion(string(output), spec.Toolchain) {
		passed = false
	}
	return commandResult{ID: spec.ID, Command: spec.Command, Toolchain: spec.Toolchain, Platform: spec.Platform, StartedAt: timestamp(started), FinishedAt: timestamp(time.Now().UTC()), ExitStatus: status, Pass: passed, OutputSHA256: hex.EncodeToString(digest[:]), Output: string(output)}
}

func observedGoVersion(output, toolchain string) bool {
	fields := strings.Fields(output)
	return len(fields) >= 3 && fields[0] == "go" && fields[1] == "version" && fields[2] == toolchain
}

func loadPins(root string) (string, string, string, string, error) {
	var p00 struct {
		Images struct {
			Qualification struct{ Reference, AMD64, ARM64 string }
		}
	}
	var p01 struct {
		QualityTools struct{ Staticcheck, Govulncheck string } `json:"quality_tools"`
	}
	if err := decodeFile(filepath.Join(root, "docs/p00/evidence.json"), &p00); err != nil {
		return "", "", "", "", err
	}
	if err := decodeFile(filepath.Join(root, "docs/p01/evidence.json"), &p01); err != nil {
		return "", "", "", "", err
	}
	repository := strings.Split(p00.Images.Qualification.Reference, "@")[0]
	return repository + "@" + p00.Images.Qualification.AMD64, repository + "@" + p00.Images.Qualification.ARM64, p01.QualityTools.Staticcheck, p01.QualityTools.Govulncheck, nil
}

func priorBindings(root string) []priorReport {
	result := make([]priorReport, 0, 9)
	for phase := 3; phase <= 11; phase++ {
		phaseName := fmt.Sprintf("p%02d", phase)
		paths := []string{"docs/" + phaseName + "/integration-report.json"}
		if phase == 5 {
			matches, _ := filepath.Glob(filepath.Join(root, "testdata/p05/*"))
			paths = paths[:0]
			for _, match := range matches {
				if info, err := os.Stat(match); err == nil && info.Mode().IsRegular() {
					relative, _ := filepath.Rel(root, match)
					paths = append(paths, filepath.ToSlash(relative))
				}
			}
			sort.Strings(paths)
		}
		artifacts := make(map[string]string, len(paths))
		for _, path := range paths {
			if digest, err := hashFile(filepath.Join(root, filepath.FromSlash(path))); err == nil {
				artifacts[path] = digest
			}
		}
		result = append(result, priorReport{Phase: phaseName, VerifierCommand: "CGO_ENABLED=0 GOTOOLCHAIN=" + latestGo + " go run ./tools/" + phaseName + "-verify", CheckID: "verify-" + phaseName, Artifacts: artifacts})
	}
	return result
}

func sourceArtifacts(root string) (map[string]string, error) {
	result := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if relative == ".git" || relative == "docs/p12/release-artifacts" {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || relative == "docs/p12/qualification-report.json" || relative == "docs/p12/human-review.json" || relative == "integration/p12/report.json" || relative == p12fuzzevidence.ReportPath {
			return nil
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		result[relative] = digest
		return nil
	})
	return result, err
}

func validateInventory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	header, err := reader.Read()
	if err != nil {
		return err
	}
	disposition := slices.Index(header, "disposition")
	phase := slices.Index(header, "phase")
	if disposition < 0 || phase < 0 {
		return errors.New("missing disposition or phase column")
	}
	for row := 2; ; row++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("row %d: %w", row, err)
		}
		if record[disposition] == "review-required" || strings.EqualFold(record[phase], "planned") {
			return fmt.Errorf("row %d remains planned or review-required", row)
		}
	}
	return nil
}

func decodeObservation(output string) *platformObservation {
	var value platformObservation
	if json.Unmarshal([]byte(output), &value) != nil {
		return nil
	}
	return &value
}

func hashDirectory(path string) map[string]string {
	result := make(map[string]string)
	entries, err := os.ReadDir(path)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			if digest, err := hashFile(filepath.Join(path, entry.Name())); err == nil {
				result[entry.Name()] = digest
			}
		}
	}
	return result
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func mapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func decodeFile(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(target)
}

func writeReport(path string, value qualificationReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	file, err := os.Create(temporary)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func timestamp(value time.Time) string    { return value.Format(time.RFC3339Nano) }
func fatalf(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...); os.Exit(1) }
