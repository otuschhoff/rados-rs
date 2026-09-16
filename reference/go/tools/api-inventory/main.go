// Command api-inventory extracts the public librados API from pinned Ceph headers.
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type entry struct {
	language  string
	owner     string
	symbol    string
	signature string
}

type classification struct {
	goEquivalent string
	disposition  string
	phase        string
	prerequisite string
	difference   string
	test         string
}

var implementedClassifications = map[string]classification{
	"rados_read_op_set_flags": {
		"rados.ReadOp.SetFlags", "implemented", "P08", "replicated pools on certified Ceph 20.2.4",
		"Exposes the qualified FAILOK sub-operation flag; rejects unknown flags", "P08 unit and live compound FAILOK tests",
	},
	"rados_write_op_set_flags": {
		"rados.WriteOp.SetFlags", "implemented", "P08", "replicated pools on certified Ceph 20.2.4",
		"Exposes the qualified FAILOK sub-operation flag; preserves typed create flags", "P08 unit and live compound FAILOK tests",
	},
	"rados_write_op_omap_rm_range2": {
		"rados.WriteOp.RemoveOMAPRange", "implemented", "P08", "replicated pools on certified Ceph 20.2.4",
		"Binary-safe half-open key range in a server-owned compound", "P08 codec and live metadata tests",
	},
	"IoCtx::omap_get_header": {
		"rados.ObjectRef.GetOMAPHeader", "implemented", "P08", "replicated pools on certified Ceph 20.2.4",
		"Returns caller-owned header bytes", "P08 unit and live metadata tests",
	},
	"IoCtx::omap_get_vals_by_keys": {
		"rados.ObjectRef.GetOMAP", "implemented", "P08", "replicated pools on certified Ceph 20.2.4",
		"Binary-safe key selection returns caller-owned entries", "P08 codec and live metadata tests",
	},
	"ObjectReadOperation::omap_get_header": {
		"rados.ReadOp.GetOMAPHeader", "implemented", "P08", "replicated pools on certified Ceph 20.2.4",
		"Ordered compound result uses Go-owned bytes", "P08 unit and live compound tests",
	},
	"rados_aio_flush": {
		"rados.Client.Flush", "implemented", "P07", "replicated pools on certified Ceph 20.2.4",
		"Watermark-based context-aware drain; no public C completion allocation", "P07 mutation/flush unit and live-cluster tests",
	},
	"rados_aio_flush_async": {
		"rados.Client.Flush", "implemented", "P07", "replicated pools on certified Ceph 20.2.4",
		"Unified context-aware drain; no callback completion allocation", "P07 mutation/flush unit and live-cluster tests",
	},
	"rados_append": {
		"rados.ObjectRef.Append", "implemented", "P07", "replicated pools on certified Ceph 20.2.4",
		"Returns OpResult version; ambiguity is surfaced as outcome unknown", "P07 native/Go CRUD and primary-remap append-once tests",
	},
	"rados_remove": {
		"rados.ObjectRef.Remove", "implemented", "P07", "replicated pools on certified Ceph 20.2.4",
		"Context-aware and returns OpResult version", "P07 native/Go CRUD and missing-object tests",
	},
	"rados_trunc": {
		"rados.ObjectRef.Truncate", "implemented", "P07", "replicated pools on certified Ceph 20.2.4",
		"Context-aware and returns OpResult version", "P07 native/Go CRUD tests",
	},
	"rados_write": {
		"rados.ObjectRef.Write", "implemented", "P07", "replicated pools on certified Ceph 20.2.4",
		"Checked offsets; copied input; returns OpResult version", "P07 native/Go CRUD tests",
	},
	"rados_write_full": {
		"rados.ObjectRef.WriteFull", "implemented", "P07", "replicated pools on certified Ceph 20.2.4",
		"Atomic full replacement; copied input; returns OpResult version", "P07 native/Go CRUD and benchmark tests",
	},
}

var (
	commentRE = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)
	spaceRE   = regexp.MustCompile(`\s+`)
	cNameRE   = regexp.MustCompile(`\b(rados_[A-Za-z0-9_]+)\s*\(`)
	classRE   = regexp.MustCompile(`\b(class|struct)\s+(?:CEPH_RADOS_API\s+)?([A-Za-z_][A-Za-z0-9_]*)[^;{]*\{`)
	methodRE  = regexp.MustCompile(`(?m)^[ \t]*(?:explicit\s+)?(?:static\s+)?(?:virtual\s+)?(?:[A-Za-z_~][^;{}()]*?\s+[*&]*\s*)?(operator\s*(?:\[\]|->|<<|==|!=|=|<|\*|\+\+)|[A-Za-z_~][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:__attribute__\s*\(\([^;{}]*\)\)\s*)?(?:=[^;]+)?;`)
	inlineRE  = regexp.MustCompile(`(?m)^[ \t]*(?:explicit\s+)?(?:virtual\s+)?([A-Za-z_~][A-Za-z0-9_]*)\s*\([^;{}\n]*\)(?:\s*:\s*[^{}\n]+)?\s*(?:override\s*)?\{[^{}\n]*\}`)
	freeCPPRE = regexp.MustCompile(`CEPH_RADOS_API\s+([^;{}]*?\b(operator[^[:space:]<(]*|[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)[^;{}]*);`)
)

func main() {
	cHeader := flag.String("c", "", "path to librados.h")
	cppHeader := flag.String("cpp", "", "path to librados.hpp")
	output := flag.String("output", "", "output CSV path, or stdout when empty")
	flag.Parse()
	if *cHeader == "" || *cppHeader == "" {
		fatalf("both -c and -cpp are required")
	}

	entries := append(extractC(read(*cHeader)), extractCPP(read(*cppHeader))...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].language != entries[j].language {
			return entries[i].language < entries[j].language
		}
		if entries[i].owner != entries[j].owner {
			return entries[i].owner < entries[j].owner
		}
		if entries[i].symbol != entries[j].symbol {
			return entries[i].symbol < entries[j].symbol
		}
		return entries[i].signature < entries[j].signature
	})

	var destination = os.Stdout
	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			fatalf("create output: %v", err)
		}
		defer file.Close()
		destination = file
	}

	writer := csv.NewWriter(destination)
	must(writer.Write([]string{"language", "owner", "source_symbol", "source_signature", "go_equivalent", "disposition", "phase", "prerequisites", "semantic_difference", "conformance_test"}))
	seen := make(map[string]struct{}, len(entries))
	for _, item := range entries {
		key := item.language + ":" + item.owner + ":" + item.symbol + ":" + item.signature
		if _, exists := seen[key]; exists {
			fatalf("duplicate extracted API key %q", key)
		}
		seen[key] = struct{}{}
		result, implemented := implementedClassifications[item.symbol]
		if !implemented {
			result.goEquivalent, result.disposition, result.phase, result.difference, result.test = classify(item)
			result.prerequisite = prerequisites(result.phase)
		}
		must(writer.Write([]string{item.language, item.owner, item.symbol, item.signature, result.goEquivalent, result.disposition, result.phase, result.prerequisite, result.difference, result.test}))
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fatalf("write output: %v", err)
	}
	fmt.Fprintf(os.Stderr, "inventory: %d C APIs, %d C++ operations\n", count(entries, "C"), count(entries, "C++"))
}

func extractC(source string) []entry {
	source = commentRE.ReplaceAllString(source, " ")
	var entries []entry
	for _, statement := range strings.Split(source, ";") {
		if !strings.Contains(statement, "CEPH_RADOS_API") {
			continue
		}
		match := cNameRE.FindStringSubmatch(statement)
		if match == nil {
			continue
		}
		entries = append(entries, entry{language: "C", owner: "global", symbol: match[1], signature: normalize(statement + ";")})
	}
	return entries
}

func extractCPP(source string) []entry {
	source = commentRE.ReplaceAllString(source, " ")
	var entries []entry
	for _, class := range publicClassBodies(source) {
		body := publicSections(class.body, class.kind == "struct")
		for _, match := range methodRE.FindAllStringSubmatch(body, -1) {
			name := match[1]
			if name == "if" || name == "for" || name == "while" || name == "__attribute__" {
				continue
			}
			signature := strings.TrimLeft(match[0], ";{}")
			entries = append(entries, entry{language: "C++", owner: class.name, symbol: class.name + "::" + name, signature: normalize(signature)})
		}
		for _, match := range inlineRE.FindAllStringSubmatch(body, -1) {
			entries = append(entries, entry{language: "C++", owner: class.name, symbol: class.name + "::" + match[1], signature: normalize(match[0])})
		}
	}
	for _, match := range freeCPPRE.FindAllStringSubmatch(source, -1) {
		entries = append(entries, entry{language: "C++", owner: "global", symbol: match[2], signature: normalize(match[0])})
	}
	return entries
}

type classBody struct {
	kind string
	name string
	body string
}

func publicClassBodies(source string) []classBody {
	var result []classBody
	for _, location := range classRE.FindAllStringSubmatchIndex(source, -1) {
		start := location[1]
		depth := 1
		end := start
		for end < len(source) && depth > 0 {
			switch source[end] {
			case '{':
				depth++
			case '}':
				depth--
			}
			end++
		}
		if depth == 0 {
			result = append(result, classBody{kind: source[location[2]:location[3]], name: source[location[4]:location[5]], body: source[start : end-1]})
		}
	}
	return result
}

func publicSections(body string, initiallyPublic bool) string {
	var result strings.Builder
	visibility := "private"
	if initiallyPublic {
		visibility = "public"
	}
	for scanner := bufio.NewScanner(strings.NewReader(body)); scanner.Scan(); {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "public:":
			visibility = "public"
		case "private:", "protected:":
			visibility = "private"
		default:
			if visibility == "public" {
				result.WriteString(line)
				result.WriteByte('\n')
			}
		}
	}
	return result.String()
}

func classify(item entry) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	if strings.Contains(item.signature, "deprecated") || containsAny(lower, "watchctx::notify", "get_auid", "set_auid", "tmap_") {
		return "none", "intentional-omission: deprecated or legacy API without distinct v1 behavior", "P13", "No deprecated compatibility alias in the initial Go API", "inventory review; no runtime conformance claim"
	}
	if containsAny(lower, "monitor_log", "service_register", "service_daemon", "service_update", "base_tier", "cache_", "hit_set") {
		return "none", "deferred: legacy cache tier or service/log subscription API", "P13", "Outside the v1 scope defined by SPEC.md", "future explicit qualification"
	}
	if lower == "rados_buffer_free" || containsAny(lower, "release_", "_destroy") || strings.HasPrefix(lower, "~") || strings.Contains(lower, "::~") {
		return "automatic Go memory ownership", "go-native", "P01", "No public deallocator", "ownership and leak tests"
	}
	switch {
	case strings.Contains(lower, "::operator") || strings.HasSuffix(lower, "::dup") || strings.HasSuffix(lower, "::is_valid"):
		return "Go value, iterator, and ownership semantics", "go-native", "P01", "C++ copy/move/operator surface is represented by idiomatic Go values", "ownership and iterator tests"
	case strings.Contains(lower, "::") && (strings.HasSuffix(lower, "::ioctx") || strings.HasSuffix(lower, "::rados") || strings.HasSuffix(lower, "::objectcursor") || strings.HasSuffix(lower, "::objectoperation") || strings.HasSuffix(lower, "::placementgroup")):
		return "Go constructors and immutable value/builders", "go-native", "P01", "Constructors and move/copy rules become Go constructors and ownership rules", "API lifecycle tests"
	case isAny(lower, "rados_create", "rados_create2", "rados_create_with_context", "rados_version", "rados::version") || containsAny(lower, "::init", "connect", "shutdown", "conf_", "config", "cct", "instance_id", "ioctx::close", "ioctx_destroy", "ioctx_get_cluster"):
		return classifyConfigLifecycle(item)
	case containsAny(lower, "pool_create", "pool_delete", "application_", "cluster_stat", "pool_stat", "mon_command", "mgr_command", "osd_command", "pg_command", "blocklist", "blacklist"):
		return classifyP11(item, "rados.Client administrative methods")
	case containsAny(lower, "pool_list", "pool_lookup", "pool_reverse", "ioctx_create", "get_pool_name", "get_id", "cluster_fsid", "wait_for_latest_osdmap", "min_compatible", "ping_monitor"):
		return classifyDiscovery(item)
	case containsAny(lower, "watch", "notify"):
		return classifyP09(item, "rados.Watch and notify methods", "watch/notify")
	case containsAny(lower, "lock", "break_lock", "list_lockers"):
		return classifyP09(item, "rados lock methods", "lock")
	case containsAny(lower, "snap"):
		return classifyP10(item, "rados snapshot methods and immutable snapshot views", "snapshot and EC")
	case containsAny(lower, "omap", "xattr"):
		return classifyP08(item, "rados metadata methods / operation builders")
	case containsAny(lower, "nobjects", "object_list", "objectiterator", "listobject", "objectcursor", "get_locator", "get_nspace"):
		return classifyP08(item, "rados object iterator and cursor")
	case containsAny(lower, "exec"):
		return classifyP09(item, "rados class execution methods", "class/lock/watch")
	case containsAny(lower, "checksum", "writesame", "sparse", "clone", "copy", "alloc_hint", "mapext", "alignment"):
		return classifyP10(item, "rados specialized object methods", "specialized object")
	case containsAny(lower, "read_op", "write_op", "objectreadoperation", "objectwriteoperation", "operate", "assert", "cmp", "objectoperation", "set_op_flags", "full_try", "full_force", "::size"):
		return classifyP08(item, "rados.ReadOp / rados.WriteOp")
	case containsAny(lower, "read", "stat"):
		return classifyReadStat(item)
	case containsAny(lower, "write", "append", "truncate", "trunc", "remove", "zero", "ioctx::create"):
		return classifyMutation(item)
	case containsAny(lower, "aio", "completion", "flush", "get_last_version"):
		return classifyCompletion(item)
	case containsAny(lower, "set_namespace", "get_namespace", "locator_set_key", "get_object_pg_hash_position", "get_object_hash_position", "placementgroup::parse"):
		return classifyViewPlacement(item)
	case containsAny(lower, "inconsistent"):
		return classifyP11(item, "rados.Client administrative consistency methods")
	case lower == "rados_getaddrs" || containsAny(lower, "get_addrs"):
		return classifyP11(item, "rados.Client session addresses")
	case containsAny(lower, "from_rados_t", "from_rados_ioctx_t"):
		return "none", "intentional-omission: native handle interoperation violates pure-Go boundary", "P00", "No C handle exists in the distributed client", "dependency and cgo audit"
	case containsAny(lower, "full_try", "full_force"):
		return "rados operation flags", "intentional-omission: non-frozen P08 variant", "P08", "Not exposed by the certified P08 Go contract", "P08 API inventory review; no runtime conformance claim"
	case containsAny(lower, "to_str", "::set"):
		return "Go String/value semantics", "go-native", "P08", "Represented by Go value methods", "cursor round-trip tests"
	default:
		return "none", "review-required", "P00", "Must be classified before P00 exit", "classification validator"
	}
}

func classifyConfigLifecycle(item entry) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	if isAny(lower, "rados_version", "rados::version") {
		return "none", "intentional-omission: version API absent from frozen v1 contract", "P01", "The pure-Go module does not report a linked librados version", "P01 API inventory review; no runtime conformance claim"
	}
	if containsAny(lower, "cct", "ioctx_get_cluster") {
		return "none", "intentional-omission: native handle access violates pure-Go boundary", "P01", "No native configuration or cluster handle exists", "P01 dependency and cgo audit"
	}
	if isAny(lower, "rados_create", "rados_create2", "rados_create_with_context", "rados::init", "rados::init2", "rados::init_with_context") {
		return "rados.New", "go-native", "P01/P04", "Go construction combines native allocation, initialization, and ownership", "P01 lifecycle and P04 configuration tests"
	}
	return "rados.Client / rados.Config lifecycle and configuration methods", "implemented", "P01/P04", "Typed, value-oriented configuration and context-aware lifecycle replace mutable native configuration", "P01 lifecycle and P04 configuration tests"
}

func classifyDiscovery(item entry) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	if containsAny(lower, "min_compatible", "ping_monitor", "wait_for_latest_osdmap") {
		return "none", "intentional-omission: discovery diagnostic absent from frozen v1 contract", "P04", "No distinct v1 behavior requires this native diagnostic or explicit map wait", "P04 API inventory review; no runtime conformance claim"
	}
	return "rados.Client pool/map discovery methods", "implemented", "P04", "Context-aware discovery returns Go-owned values and immutable pool views", "P04 unit and live discovery tests"
}

func classifyViewPlacement(item entry) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	if containsAny(lower, "get_object_pg_hash_position", "get_object_hash_position", "placementgroup::parse") {
		return "none", "intentional-omission: placement diagnostic absent from frozen v1 contract", "P05", "Public hash-position diagnostics and placement-group parsing are not v1-required behavior", "P05 API inventory review; no runtime conformance claim"
	}
	return "rados.Pool.WithNamespace / rados.Pool.WithLocator", "implemented", "P05", "Immutable pool views replace mutable ioctx namespace and locator state", "P05 unit and live placement tests"
}

func classifyReadStat(item entry) (goEquivalent, disposition, phase, difference, test string) {
	if containsAny(strings.ToLower(item.symbol), "aio_") {
		return "rados.ObjectRef.Read / rados.ObjectRef.Stat", "go-native", "P06", "Context-aware methods and Go-owned results replace native completion and output buffers", "P06 context, ownership, and live read/stat tests"
	}
	return "rados.ObjectRef.Read / rados.ObjectRef.Stat", "implemented", "P06", "Context-aware reads return Go-owned data and ObjectInfo", "P06 unit and live read/stat tests"
}

func classifyMutation(item entry) (goEquivalent, disposition, phase, difference, test string) {
	if containsAny(strings.ToLower(item.symbol), "aio_") {
		return "rados.ObjectRef mutation methods", "go-native", "P07", "Context-aware methods and OpResult replace native completion and callback forms", "P07 context, result, and live mutation tests"
	}
	return "rados.ObjectRef mutation methods", "implemented", "P07", "Context-aware mutations return versioned OpResult values", "P07 unit and live mutation tests"
}

func classifyCompletion(item entry) (goEquivalent, disposition, phase, difference, test string) {
	return "context.Context, operation results, and rados.Client.Flush", "go-native", "P07", "Go context, direct results, and flush semantics replace native completions, callbacks, and last-version state", "P07 context, completion, result, and flush tests"
}

func classifyP11(item entry, equivalent string) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	if containsAny(lower, "command_target", "pool_create_with_crush_rule", "test_blocklist_self") {
		return equivalent, "intentional-omission: non-frozen P11 variant", "P11", "Not exposed by the certified P11 Go contract", "P11 API inventory review; no runtime conformance claim"
	}
	if containsAny(lower, "_async") {
		return equivalent, "go-native", "P11", "Context-aware Go calls replace native completion allocation", "P11 context, ownership, and live administrative tests"
	}
	return equivalent, "implemented", "P11", "Context-aware Go values preserve native semantics with Go-owned command and metadata results", "P11 unit and live administrative interoperability tests"
}

func classifyP10(item entry, equivalent, surface string) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	if containsAny(lower, "mapext", "list_snaps", "get_inconsistent_snapsets", "set_alloc_hint2") || isAny(lower, "ioctx::pool_required_alignment", "ioctx::pool_requires_alignment") {
		return equivalent, "intentional-omission: non-frozen P10 variant", "P10", "Not exposed by the certified P10 Go contract", "P10 API inventory review; no runtime conformance claim"
	}
	if containsAny(lower, "rados_aio_", "::aio_") {
		return equivalent, "go-native", "P10", "Context-aware Go calls and Go-owned results replace native completion and buffer lifetimes", "P10 context, ownership, and live " + surface + " tests"
	}
	return equivalent, "implemented", "P10", "Context-aware Go values preserve native semantics with Go-owned inputs and results", "P10 unit and live " + surface + " interoperability tests"
}

func classifyP09(item entry, equivalent, surface string) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	disposition = "implemented"
	difference = "Unified context-aware Go calls preserve native semantics and use Go-owned results"
	if containsAny(lower, "watch_flush", "decode_notify_response", "free_notify_response") {
		disposition = "go-native"
		difference = "Watch draining and notify reply memory ownership are integrated into Go lifecycle and result semantics"
	}
	return equivalent, disposition, "P09", difference, "P09 unit and live " + surface + " interoperability tests"
}

func classifyP08(item entry, equivalent string) (goEquivalent, disposition, phase, difference, test string) {
	lower := strings.ToLower(item.symbol)
	if containsAny(lower, "_end", "_next", "_close", "_free", "::listobject", "::nobjectiterator", "::objectcursor", "::objectreadoperation", "::objectwriteoperation", "objectoperationcompletion") {
		return equivalent, "go-native", "P08", "Go values, pages, and builders replace native iterator and allocation lifetimes", "P08 ownership, pagination, and builder lifecycle tests"
	}
	if isAny(lower, "rados_read_op_cmpext", "rados_read_op_omap_cmp", "rados_read_op_omap_cmp2") || containsAny(lower, "cmpxattr", "full_try", "full_force", "set_filter", "set_chunk", "is_dirty", "tier_", "::mtime", "redirect", "undirty", "manifest", "get_pg_hash_position", "::size") {
		return equivalent, "intentional-omission: non-frozen P08 variant", "P08", "Not exposed by the certified P08 Go contract", "P08 API inventory review; no runtime conformance claim"
	}
	return equivalent, "implemented", "P08", "Context-aware Go values, pages, and builders preserve the operation semantics", "P08 unit and live metadata, compound, enumeration, and map-change tests"
}

func isAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}

func prerequisites(phase string) string {
	if phase == "P00" || phase == "P01" {
		return "none"
	}
	return "completion of prior phases; see SPEC.md"
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func normalize(value string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(value, " "))
}

func read(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func count(entries []entry, language string) int {
	total := 0
	for _, item := range entries {
		if item.language == language {
			total++
		}
	}
	return total
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "api-inventory: "+format+"\n", args...)
	os.Exit(1)
}
