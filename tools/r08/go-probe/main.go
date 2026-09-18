package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	rados "github.com/otuschhoff/rados-go"
)

const payloadBytes = 4096
const operations = 128

type suiteReport struct {
	Create      bool        `json:"create"`
	Write       bool        `json:"write"`
	WriteFull   bool        `json:"write_full"`
	Append      bool        `json:"append"`
	Truncate    bool        `json:"truncate"`
	Zero        bool        `json:"zero"`
	Remove      bool        `json:"remove"`
	Performance performance `json:"performance"`
}

type performance struct {
	Implementation         string           `json:"implementation"`
	Workload               string           `json:"workload"`
	PayloadBytes           int              `json:"payload_bytes"`
	Concurrency            int              `json:"concurrency"`
	Operations             int              `json:"operations"`
	ElapsedSeconds         float64          `json:"elapsed_seconds"`
	OperationsPerSecond    float64          `json:"operations_per_second"`
	LatencyP50Microseconds float64          `json:"latency_p50_microseconds"`
	LatencyP95Microseconds float64          `json:"latency_p95_microseconds"`
	LatencyP99Microseconds float64          `json:"latency_p99_microseconds"`
	CPUUserSeconds         float64          `json:"cpu_user_seconds"`
	CPUSystemSeconds       float64          `json:"cpu_system_seconds"`
	AllocationMetric       allocationMetric `json:"allocation_metric"`
	RetainedBytes          uint64           `json:"retained_bytes"`
	PeakRSSBytes           uint64           `json:"peak_rss_bytes"`
}

type allocationMetric struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "r08 Go probe:", err)
		os.Exit(1)
	}
}

func run() error {
	action := flag.String("action", "", "suite or cross-require-write")
	monitors := flag.String("monitors", "", "comma-separated v2 monitor endpoints")
	keyFile := flag.String("key", "", "file containing an encoded CephX key")
	fsid := flag.String("fsid", "", "expected cluster FSID")
	expect := flag.String("expect", "", "expected cross-client value")
	value := flag.String("value", "", "replacement cross-client value")
	flag.Parse()
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client, err := rados.New(rados.Config{Monitors: strings.Split(*monitors, ","), Entity: "client.r08", ClusterFSID: *fsid, Key: bytes.TrimSpace(key), OperationTimeout: 60 * time.Second})
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Connect(ctx); err != nil {
		return err
	}
	pool, err := client.OpenPool(ctx, "r08-data")
	if err != nil {
		return err
	}
	switch *action {
	case "suite":
		report, err := runSuite(ctx, client, pool)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	case "cross-require-write":
		object := pool.Object("cross-client")
		actual, _, err := object.Read(ctx, 0, 4096)
		if err != nil || string(actual) != *expect {
			return fmt.Errorf("cross-client value %q: %w", actual, err)
		}
		_, err = object.WriteFull(ctx, []byte(*value))
		return err
	default:
		return fmt.Errorf("unsupported -action %q", *action)
	}
}

func runSuite(ctx context.Context, client *rados.Client, pool rados.Pool) (suiteReport, error) {
	object := pool.Object("go-mutations")
	_, _ = object.Remove(ctx)
	if _, err := object.Create(ctx, true); err != nil {
		return suiteReport{}, err
	}
	if _, err := object.Write(ctx, 0, []byte("abcdef")); err != nil {
		return suiteReport{}, err
	}
	if err := requireRead(ctx, object, []byte("abcdef")); err != nil {
		return suiteReport{}, err
	}
	if _, err := object.WriteFull(ctx, []byte("0123456789")); err != nil {
		return suiteReport{}, err
	}
	if _, err := object.Append(ctx, []byte("AB")); err != nil {
		return suiteReport{}, err
	}
	if err := requireRead(ctx, object, []byte("0123456789AB")); err != nil {
		return suiteReport{}, err
	}
	if _, err := object.Truncate(ctx, 8); err != nil {
		return suiteReport{}, err
	}
	if _, err := object.Zero(ctx, 2, 3); err != nil {
		return suiteReport{}, err
	}
	if err := requireRead(ctx, object, []byte{'0', '1', 0, 0, 0, '5', '6', '7'}); err != nil {
		return suiteReport{}, err
	}
	if _, err := pool.Object("go-flush-a").WriteFull(ctx, []byte("first")); err != nil {
		return suiteReport{}, err
	}
	if _, err := pool.Object("go-flush-b").WriteFull(ctx, []byte("second")); err != nil {
		return suiteReport{}, err
	}
	if err := client.Flush(ctx); err != nil {
		return suiteReport{}, err
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := object.Append(cancelled, []byte("never")); !errors.Is(err, context.Canceled) {
		return suiteReport{}, fmt.Errorf("pre-cancelled append returned %v", err)
	}
	if err := client.Flush(ctx); err != nil {
		return suiteReport{}, err
	}
	if err := requireRead(ctx, object, []byte{'0', '1', 0, 0, 0, '5', '6', '7'}); err != nil {
		return suiteReport{}, err
	}
	if _, err := object.Remove(ctx); err != nil {
		return suiteReport{}, err
	}
	if _, _, err := object.Read(ctx, 0, 1); !errors.Is(err, rados.ErrNotFound) {
		return suiteReport{}, fmt.Errorf("removed object returned %v", err)
	}
	measured, err := benchmark(ctx, pool)
	if err != nil {
		return suiteReport{}, err
	}
	return suiteReport{true, true, true, true, true, true, true, measured}, nil
}

func benchmark(ctx context.Context, pool rados.Pool) (performance, error) {
	payload := make([]byte, payloadBytes)
	for index := range payload {
		payload[index] = byte(index)
	}
	object := pool.Object("go-performance")
	if _, err := object.WriteFull(ctx, payload); err != nil {
		return performance{}, err
	}
	runtime.GC()
	var memoryBefore, memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	userBefore, systemBefore, peakBefore, err := resources()
	if err != nil {
		return performance{}, err
	}
	latencies := make([]float64, 0, operations)
	started := time.Now()
	for index := 0; index < operations; index++ {
		operationStarted := time.Now()
		if _, err := object.WriteFull(ctx, payload); err != nil {
			return performance{}, err
		}
		latencies = append(latencies, float64(time.Since(operationStarted).Nanoseconds())/1000)
	}
	elapsed := time.Since(started).Seconds()
	userAfter, systemAfter, peakAfter, err := resources()
	if err != nil {
		return performance{}, err
	}
	runtime.ReadMemStats(&memoryAfter)
	sort.Float64s(latencies)
	peak := peakAfter
	if peakBefore > peak {
		peak = peakBefore
	}
	return performance{
		Implementation: "go", Workload: "write-full-baseline-v1", PayloadBytes: payloadBytes,
		Concurrency: 1, Operations: operations, ElapsedSeconds: elapsed,
		OperationsPerSecond:    operations / elapsed,
		LatencyP50Microseconds: percentile(latencies, 50), LatencyP95Microseconds: percentile(latencies, 95), LatencyP99Microseconds: percentile(latencies, 99),
		CPUUserSeconds: userAfter - userBefore, CPUSystemSeconds: systemAfter - systemBefore,
		AllocationMetric: allocationMetric{Name: "runtime_total_alloc_bytes", Value: memoryAfter.TotalAlloc - memoryBefore.TotalAlloc},
		RetainedBytes:    payloadBytes, PeakRSSBytes: peak,
	}, nil
}

func requireRead(ctx context.Context, object rados.ObjectRef, expected []byte) error {
	actual, _, err := object.Read(ctx, 0, 1<<20)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("content mismatch: got %x want %x", actual, expected)
	}
	return nil
}

func percentile(values []float64, percentile int) float64 {
	return values[(len(values)-1)*percentile/100]
}

func resources() (float64, float64, uint64, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, 0, 0, err
	}
	seconds := func(value syscall.Timeval) float64 { return float64(value.Sec) + float64(value.Usec)/1e6 }
	return seconds(usage.Utime), seconds(usage.Stime), uint64(usage.Maxrss) * 1024, nil
}
