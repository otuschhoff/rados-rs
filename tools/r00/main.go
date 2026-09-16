package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type FileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
	Mode   int64  `json:"mode"`
}

type Baseline struct {
	SchemaVersion int          `json:"schema_version"`
	Repository    string       `json:"repository"`
	Head          string       `json:"head"`
	CaptureKind   string       `json:"capture_kind"`
	DirtyStatus   string       `json:"dirty_status"`
	Archive       string       `json:"archive"`
	ArchiveSHA256 string       `json:"archive_sha256"`
	Files         []FileRecord `json:"files"`
	Excluded      string       `json:"excluded"`
}

type Import struct {
	Source      string `json:"source_path"`
	Destination string `json:"destination"`
	SHA256      string `json:"sha256"`
	Disposition string `json:"disposition"`
	License     string `json:"license_provenance"`
}

type Public struct {
	ID     string `json:"id"`
	Symbol string `json:"symbol"`
	Kind   string `json:"kind"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Phase  string `json:"phase"`
}

func main() {
	source := flag.String("source", "", "Go source checkout for explicit capture")
	root := flag.String("root", ".", "rados-rs repository root")
	verify := flag.Bool("verify", false, "verify existing archive, imports and inventories without Go checkout")
	flag.Parse()
	var err error
	if *verify {
		err = verifyRoot(*root)
	} else if *source == "" {
		err = fmt.Errorf("capture requires -source; use -verify for offline validation")
	} else {
		err = capture(*source, *root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func command(root string, arguments ...string) ([]byte, error) {
	cmd := exec.Command(arguments[0], arguments[1:]...)
	cmd.Dir = root
	return cmd.Output()
}

func write(root, name string, data []byte) error {
	filename := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func writeJSON(root, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return write(root, name, append(data, '\n'))
}

func capture(source, root string) error {
	if _, err := os.Stat(filepath.Join(root, "reference/go-baseline.json")); err == nil {
		return fmt.Errorf("baseline already exists; use a separately reviewed import update, not overwrite")
	}
	head, err := command(source, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	status, err := command(source, "git", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return err
	}
	listing, err := command(source, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	if err != nil {
		return err
	}
	contents := map[string][]byte{}
	modes := map[string]int64{}
	for _, name := range strings.Split(string(listing), "\x00") {
		if name == "" {
			continue
		}
		info, statErr := os.Lstat(filepath.Join(source, name))
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return statErr
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("nonregular source: %s", name)
		}
		data, readErr := os.ReadFile(filepath.Join(source, name))
		if readErr != nil {
			return readErr
		}
		contents[name] = data
		modes[name] = 0644
		if info.Mode()&0111 != 0 {
			modes[name] = 0755
		}
	}
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	var archive bytes.Buffer
	compressor := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressor)
	baseline := Baseline{SchemaVersion: 1, Repository: "https://github.com/otuschhoff/go-librados.git", Head: strings.TrimSpace(string(head)), CaptureKind: "content-addressed-working-tree", DirtyStatus: string(status), Excluded: "git metadata, ignored files, absent/deleted files; no clean-commit or test-pass claim"}
	for _, name := range names {
		data := contents[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: modes[name], Size: int64(len(data)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
		baseline.Files = append(baseline.Files, FileRecord{name, digest(data), len(data), modes[name]})
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := compressor.Close(); err != nil {
		return err
	}
	baseline.ArchiveSHA256 = digest(archive.Bytes())
	baseline.Archive = "reference/archives/go-" + baseline.ArchiveSHA256 + ".tar.gz"
	statusAfter, err := command(source, "git", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return err
	}
	if !bytes.Equal(status, statusAfter) {
		return fmt.Errorf("Go status changed during capture")
	}
	for _, name := range names {
		data, readErr := os.ReadFile(filepath.Join(source, name))
		if readErr != nil || !bytes.Equal(data, contents[name]) {
			return fmt.Errorf("Go source changed during capture: %s", name)
		}
	}
	if err := write(root, baseline.Archive, archive.Bytes()); err != nil {
		return err
	}
	if err := writeJSON(root, "reference/go-baseline.json", baseline); err != nil {
		return err
	}
	linkPattern := regexp.MustCompile(`\]\(([^)]+)\)`)
	spec := string(contents["docs/RUST_PORT_SPEC.md"])
	selected := map[string]bool{}
	for _, match := range linkPattern.FindAllStringSubmatch(spec, -1) {
		target := strings.Split(match[1], "#")[0]
		if strings.HasPrefix(target, "https:") {
			continue
		}
		selected[filepath.ToSlash(filepath.Clean(filepath.Join("docs", target)))] = true
	}
	for _, name := range names {
		if strings.HasPrefix(name, "testdata/p01/") || strings.HasPrefix(name, "integration/p00/oracle/") || strings.HasPrefix(name, "docs/p00/") || strings.HasPrefix(name, "docs/p01/") {
			selected[name] = true
		}
	}
	for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES", "SECURITY.md", "go.mod", "go.sum", "docs/p03/README.md", "docs/p04/configuration.md", "testdata/README.md", "testdata/manifest.schema.json", "integration/README.md", "integration/p01/reproduce.sh", "tools/p01-verify/main.go", "tools/api-inventory/main.go", "internal/encoding/codec_test.go", "internal/protocol/protocol_test.go", "docs/RUST_PORT_SPEC.md"} {
		selected[name] = true
	}
	var imports []Import
	for _, name := range names {
		if !selected[name] {
			continue
		}
		destination := "reference/go/" + name
		if strings.HasPrefix(name, "testdata/") {
			destination = name
		}
		if name == "LICENSE" || name == "THIRD_PARTY_NOTICES" {
			destination = name
		}
		if err := write(root, destination, contents[name]); err != nil {
			return err
		}
		imports = append(imports, Import{name, destination, digest(contents[name]), "copy-unchanged", "Inherited LICENSE/THIRD_PARTY_NOTICES and source-specific provenance; fixture sidecars retain original review; Rust redistribution approval is not asserted"})
	}
	if err := writeJSON(root, "reference/imports.json", imports); err != nil {
		return err
	}
	bySource := map[string]string{}
	for _, imported := range imports {
		bySource[imported.Source] = imported.Destination
	}
	spec = linkPattern.ReplaceAllStringFunc(spec, func(match string) string {
		target := linkPattern.FindStringSubmatch(match)[1]
		if strings.HasPrefix(target, "https:") {
			return match
		}
		parts := strings.SplitN(target, "#", 2)
		name := filepath.ToSlash(filepath.Clean(filepath.Join("docs", parts[0])))
		destination := bySource[name]
		if len(parts) == 2 {
			destination += "#" + parts[1]
		}
		return "](" + "../" + destination + ")"
	})
	spec = strings.ReplaceAll(spec, "provisionally `rust-librados`", "named `rados-rs`")
	spec = strings.Replace(spec, "# Native Rust RADOS Client: Port Design and Execution Spec", "# rados-rs: Native Rust RADOS Client Design and Execution Spec", 1)
	spec = strings.Replace(spec, "Status: proposed; implementation is not started by this document.", "Status: R00 repository/reference setup executed; see R00 status for validation and open gates. Rust implementation begins in R01.", 1)
	spec += "\n## R00 Execution Record\n\nThis copy is maintained in rados-rs. [R00 status](r00/STATUS.md) and the\n[repository decision](decisions/0001-separate-repository.md) record execution.\nThe original spec and linked Go assets are preserved under reference/go;\nreference/go-baseline.json binds their complete archived working-tree source.\nRelative links within unchanged imported Go documents retain Go-root semantics;\nextract the verified archive to navigate that complete source tree.\n"
	if err := write(root, "docs/RUST_PORT_SPEC.md", []byte(spec)); err != nil {
		return err
	}
	public, err := publicDeclarations(contents)
	if err != nil {
		return err
	}
	if err := writeJSON(root, "reference/go-public-api.json", public); err != nil {
		return err
	}
	if err := writeLedger(root, contents, public); err != nil {
		return err
	}
	return verifyRoot(root)
}

func publicDeclarations(contents map[string][]byte) ([]Public, error) {
	var records []Public
	for filename, data := range contents {
		if strings.Contains(filename, "/") || !strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, "_test.go") {
			continue
		}
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, filename, data, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		phase := map[string]string{"client.go": "R05", "config.go": "R05", "errors.go": "R02", "object.go": "R08", "metadata.go": "R09", "coordination.go": "R10", "snapshot.go": "R11", "admin.go": "R12", "p12_diagnostics.go": "R13"}[filename]
		if phase == "" {
			phase = "R02"
		}
		add := func(symbol, kind string, position token.Pos) {
			selectedPhase := phase
			if kind == "type" || kind == "field" || kind == "const" || kind == "var" {
				selectedPhase = "R02"
			}
			if symbol == "Client.Flush" || symbol == "Client.Shutdown" || symbol == "Client.Close" {
				selectedPhase = "R08"
			}
			if symbol == "ObjectRef.Read" || symbol == "ObjectRef.Stat" {
				selectedPhase = "R07"
			}
			records = append(records, Public{"go:" + symbol, symbol, kind, filename, positions.Position(position).Line, selectedPhase})
		}
		for _, declaration := range file.Decls {
			switch decl := declaration.(type) {
			case *ast.FuncDecl:
				if !decl.Name.IsExported() {
					continue
				}
				symbol, kind := decl.Name.Name, "function"
				if decl.Recv != nil {
					receiver := decl.Recv.List[0].Type
					if pointer, ok := receiver.(*ast.StarExpr); ok {
						receiver = pointer.X
					}
					owner, ok := receiver.(*ast.Ident)
					if !ok || !owner.IsExported() {
						continue
					}
					symbol, kind = owner.Name+"."+symbol, "method"
				}
				add(symbol, kind, decl.Pos())
			case *ast.GenDecl:
				for _, specification := range decl.Specs {
					switch spec := specification.(type) {
					case *ast.TypeSpec:
						if !spec.Name.IsExported() {
							continue
						}
						add(spec.Name.Name, "type", spec.Pos())
						if structure, ok := spec.Type.(*ast.StructType); ok {
							for _, field := range structure.Fields.List {
								for _, name := range field.Names {
									if name.IsExported() {
										add(spec.Name.Name+"."+name.Name, "field", name.Pos())
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.IsExported() {
								add(name.Name, strings.ToLower(decl.Tok.String()), name.Pos())
							}
						}
					}
				}
			}
		}
	}
	sort.Slice(records, func(left, right int) bool { return records[left].ID < records[right].ID })
	return records, nil
}

func writeLedger(root string, contents map[string][]byte, public []Public) error {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	header := []string{"semantic_id", "native_symbol", "go_equivalent", "rust_api_plan", "phase", "disposition", "prerequisites", "adaptation", "baseline_evidence", "rust_test_id", "status"}
	if err := writer.Write(header); err != nil {
		return err
	}
	reader := csv.NewReader(bytes.NewReader(contents["docs/p00/api-inventory.csv"]))
	rows, err := reader.ReadAll()
	if err != nil {
		return err
	}
	columns := map[string]int{}
	for index, name := range rows[0] {
		columns[name] = index
	}
	phaseMap := map[string]string{"P00": "R00", "P01": "R02", "P02": "R03", "P03": "R04", "P04": "R05", "P05": "R06", "P06": "R07", "P07": "R08", "P08": "R09", "P09": "R10", "P10": "R11", "P11": "R12", "P12": "R13"}
	for _, row := range rows[1:] {
		get := func(name string) string { return row[columns[name]] }
		id := "native:" + get("language") + ":" + get("owner") + ":" + get("source_symbol") + ":" + digest([]byte(get("source_signature")))[:12]
		phase := phaseMap[get("phase")]
		if phase == "" {
			phase = "R12"
		}
		disposition := "port-behavior"
		state := "planned-not-implemented"
		if strings.Contains(get("disposition"), "defer") || strings.Contains(get("disposition"), "unsupported") || strings.Contains(get("disposition"), "omit") {
			disposition, state = "inherit-native-disposition", "inherited-exclusion-needs-ledger-review"
		}
		api := "Rust equivalent of " + get("go_equivalent") + "; exact signature frozen in R02/owning phase"
		if err := writer.Write([]string{id, get("source_symbol"), get("go_equivalent"), api, phase, disposition, get("prerequisites"), get("semantic_difference") + "; async Rust ownership and typed results, not C ABI", "reference/go/docs/p00/api-inventory.csv; " + get("conformance_test"), phase + ":" + id, state}); err != nil {
			return err
		}
	}
	for _, entry := range public {
		if err := writer.Write([]string{entry.ID, "see native rows by Go family; no guessed exact mapping", entry.Symbol, "rados:: equivalent for " + entry.Symbol + "; signature review pending R02/owning phase", entry.Phase, "port-public-contract", "inherited certified profile; declaration kind=" + entry.Kind, "Rust names and ownership adapted; byte identities, errors, cancellation and result meaning retained", fmt.Sprintf("archived Go %s:%d; reference/go-public-api.json", entry.File, entry.Line), entry.Phase + ":" + entry.ID, "planned-not-implemented"}); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	return write(root, "docs/r00/parity-ledger.csv", buffer.Bytes())
}

func verifyRoot(root string) error {
	readJSON := func(name string, value any) error {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return err
		}
		return json.Unmarshal(data, value)
	}
	var baseline Baseline
	if err := readJSON("reference/go-baseline.json", &baseline); err != nil {
		return err
	}
	archive, err := os.ReadFile(filepath.Join(root, baseline.Archive))
	if err != nil {
		return err
	}
	if digest(archive) != baseline.ArchiveSHA256 {
		return fmt.Errorf("archive hash mismatch")
	}
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)
	contents := map[string][]byte{}
	modes := map[string]int64{}
	for {
		header, nextErr := tarReader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		if header.Typeflag != tar.TypeReg || filepath.IsAbs(header.Name) || filepath.Clean(header.Name) != header.Name || strings.HasPrefix(header.Name, "../") {
			return fmt.Errorf("unsafe archive entry: %s", header.Name)
		}
		if _, exists := contents[header.Name]; exists {
			return fmt.Errorf("duplicate archive entry")
		}
		data, readErr := io.ReadAll(io.LimitReader(tarReader, 16<<20))
		if readErr != nil || int64(len(data)) != header.Size {
			return fmt.Errorf("invalid archive entry: %s", header.Name)
		}
		contents[header.Name], modes[header.Name] = data, header.Mode
	}
	if len(contents) != len(baseline.Files) {
		return fmt.Errorf("archive file count mismatch")
	}
	for _, record := range baseline.Files {
		data, exists := contents[record.Path]
		if !exists || digest(data) != record.SHA256 || len(data) != record.Size || modes[record.Path] != record.Mode {
			return fmt.Errorf("source mismatch: %s", record.Path)
		}
	}
	var imports []Import
	if err := readJSON("reference/imports.json", &imports); err != nil {
		return err
	}
	for _, imported := range imports {
		data, readErr := os.ReadFile(filepath.Join(root, imported.Destination))
		if readErr != nil || digest(data) != imported.SHA256 || !bytes.Equal(data, contents[imported.Source]) {
			return fmt.Errorf("import mismatch: %s", imported.Destination)
		}
	}
	var public []Public
	if err := readJSON("reference/go-public-api.json", &public); err != nil {
		return err
	}
	expectedPublic, err := publicDeclarations(contents)
	if err != nil {
		return err
	}
	actualJSON, _ := json.Marshal(public)
	expectedJSON, _ := json.Marshal(expectedPublic)
	if !bytes.Equal(actualJSON, expectedJSON) {
		return fmt.Errorf("Go declaration inventory mismatch")
	}
	ledger, err := os.ReadFile(filepath.Join(root, "docs/r00/parity-ledger.csv"))
	if err != nil {
		return err
	}
	rows, err := csv.NewReader(bytes.NewReader(ledger)).ReadAll()
	if err != nil {
		return err
	}
	nativeRows, err := csv.NewReader(bytes.NewReader(contents["docs/p00/api-inventory.csv"])).ReadAll()
	if err != nil {
		return err
	}
	if len(rows) != len(nativeRows)+len(public) {
		return fmt.Errorf("ledger coverage count mismatch")
	}
	ids := map[string]bool{}
	for _, row := range rows[1:] {
		if ids[row[0]] {
			return fmt.Errorf("duplicate semantic ID: %s", row[0])
		}
		ids[row[0]] = true
		if !regexp.MustCompile(`^R(0[0-9]|1[0-4])$`).MatchString(row[4]) {
			return fmt.Errorf("invalid phase")
		}
	}
	for _, entry := range public {
		if !ids[entry.ID] {
			return fmt.Errorf("missing public contract: %s", entry.ID)
		}
	}
	for name, data := range contents {
		if !strings.HasPrefix(name, "testdata/p01/") || !strings.HasSuffix(name, ".json") {
			continue
		}
		var manifest struct {
			Fixture string `json:"fixture"`
			SHA256  string `json:"sha256"`
			Secrets struct {
				Contains bool `json:"contains_secrets"`
			} `json:"secrets"`
			License struct {
				Redistribution string `json:"redistribution"`
				ReviewedBy     string `json:"reviewed_by"`
			} `json:"license"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return err
		}
		if digest(contents["testdata/p01/"+manifest.Fixture]) != manifest.SHA256 || manifest.Secrets.Contains || manifest.License.Redistribution != "approved" || manifest.License.ReviewedBy == "" {
			return fmt.Errorf("fixture provenance failure: %s", name)
		}
	}
	fmt.Printf("PASS: %d archived files, %d byte-identical imports, %d public Go declarations, %d native rows, %d ledger rows; P01 fixture hashes/review metadata verified.\n", len(contents), len(imports), len(public), len(nativeRows)-1, len(rows)-1)
	return nil
}
