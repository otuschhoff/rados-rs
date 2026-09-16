package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestR00ReferenceVerifies(t *testing.T) {
	if err := verifyRoot(filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
}

func TestR00RejectsTampering(t *testing.T) {
	for _, target := range []string{"reference/go-baseline.json", "testdata/p01/entity-name-client-1.bin", "docs/r00/parity-ledger.csv", "reference/go-public-api.json"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join("..", "..")
			for _, directory := range []string{"reference", "testdata", "docs/r00"} {
				err := filepath.WalkDir(filepath.Join(source, directory), func(name string, entry os.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if entry.IsDir() {
						return nil
					}
					relative, err := filepath.Rel(source, name)
					if err != nil {
						return err
					}
					data, err := os.ReadFile(name)
					if err != nil {
						return err
					}
					return write(root, relative, data)
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES"} {
				data, err := os.ReadFile(filepath.Join(source, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := write(root, name, data); err != nil {
					t.Fatal(err)
				}
			}
			if err := verifyRoot(root); err != nil {
				t.Fatalf("intact copy did not verify: %v", err)
			}
			if err := write(root, target, []byte("tampered\n")); err != nil {
				t.Fatal(err)
			}
			if err := verifyRoot(root); err == nil {
				t.Fatal("tampered evidence accepted")
			}
		})
	}
}
