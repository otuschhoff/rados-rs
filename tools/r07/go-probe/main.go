package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	rados "github.com/otuschhoff/rados-go"
)

type report struct {
	RangedRead          bool   `json:"ranged_read"`
	FullRead            bool   `json:"full_read"`
	EmptyRead           bool   `json:"empty_read"`
	NamespaceRead       bool   `json:"namespace_read"`
	LocatorRead         bool   `json:"locator_read"`
	Stat                bool   `json:"stat"`
	Missing             bool   `json:"missing"`
	PrimaryChange       bool   `json:"primary_change"`
	StatSize            uint64 `json:"stat_size"`
	StatMtimeSeconds    int64  `json:"stat_mtime_seconds"`
	StatMtimeNanosecond int    `json:"stat_mtime_nanosecond"`
	Version             uint64 `json:"version"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "r07 Go probe:", err)
		os.Exit(1)
	}
}

func run() error {
	monitors := flag.String("monitors", "", "comma-separated v2 monitor endpoints")
	keyFile := flag.String("key", "", "file containing an encoded CephX key")
	fsid := flag.String("fsid", "", "expected cluster FSID")
	dataFile := flag.String("data", "", "expected object bytes")
	control := flag.String("control", "", "primary-change synchronization directory")
	flag.Parse()
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	want, err := os.ReadFile(*dataFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client, err := rados.New(rados.Config{Monitors: strings.Split(*monitors, ","), Entity: "client.p06", ClusterFSID: *fsid, Key: bytes.TrimSpace(key), OperationTimeout: 10 * time.Second})
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	pool, err := client.OpenPool(ctx, "p06-data")
	if err != nil {
		return err
	}
	data, info, err := pool.Object("binary").Read(ctx, 3, 17)
	if err != nil || !bytes.Equal(data, want[3:20]) || info.Version == 0 {
		return fmt.Errorf("ranged read bytes=%x info=%+v: %w", data, info, err)
	}
	full, fullInfo, err := pool.Object("binary").Read(ctx, 0, uint64(len(want)+1024))
	if err != nil || !bytes.Equal(full, want) || fullInfo.Version == 0 {
		return fmt.Errorf("full read length=%d info=%+v: %w", len(full), fullInfo, err)
	}
	stat, err := pool.Object("binary").Stat(ctx)
	if err != nil || stat.Size != uint64(len(want)) || stat.ModTime.IsZero() || stat.Version == 0 {
		return fmt.Errorf("stat=%+v: %w", stat, err)
	}
	empty, _, err := pool.Object("empty").Read(ctx, 0, 1)
	if err != nil || len(empty) != 0 {
		return fmt.Errorf("empty read length=%d: %w", len(empty), err)
	}
	namespaceData, _, err := pool.WithNamespace("space").Object("namespaced").Read(ctx, 0, 64)
	if err != nil || string(namespaceData) != "namespace-value" {
		return fmt.Errorf("namespace read=%q: %w", namespaceData, err)
	}
	locatorData, _, err := pool.WithLocator("routing-key").Object("located").Read(ctx, 0, 64)
	if err != nil || string(locatorData) != "locator-value" {
		return fmt.Errorf("locator read=%q: %w", locatorData, err)
	}
	_, _, missingErr := pool.Object("missing").Read(ctx, 0, 1)
	if !errors.Is(missingErr, rados.ErrNotFound) {
		return fmt.Errorf("missing error=%v", missingErr)
	}
	if err := os.WriteFile(*control+"/ready", nil, 0o600); err != nil {
		return err
	}
	for {
		if _, err := os.Stat(*control + "/remapped"); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	after, afterInfo, err := pool.Object("binary").Read(ctx, 0, uint64(len(want)))
	if err != nil || !bytes.Equal(after, want) || afterInfo.Version == 0 {
		return fmt.Errorf("post-remap read length=%d info=%+v: %w", len(after), afterInfo, err)
	}
	return json.NewEncoder(os.Stdout).Encode(report{
		RangedRead: true, FullRead: true, EmptyRead: true, NamespaceRead: true,
		LocatorRead: true, Stat: true, Missing: true, PrimaryChange: true,
		StatSize: stat.Size, StatMtimeSeconds: stat.ModTime.Unix(),
		StatMtimeNanosecond: stat.ModTime.Nanosecond(), Version: stat.Version,
	})
}
