package main

import (
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
)

func TestRunHelpReturnsFlagHelp(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-h"}
	defer func() {
		os.Args = oldArgs
	}()

	err := run()
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run() error = %v, want flag.ErrHelp", err)
	}
}

func TestRunRejectsUnsupportedMode(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "invalid"}
	defer func() {
		os.Args = oldArgs
	}()

	err := run()
	if err == nil {
		t.Fatal("expected unsupported mode error")
	}
	if !strings.Contains(err.Error(), `unsupported mode "invalid"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunDNSRequiresTarget(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "dns"}
	defer func() {
		os.Args = oldArgs
	}()

	err := run()
	if err == nil {
		t.Fatal("expected missing target error")
	}
	if !strings.Contains(err.Error(), "-target is required in DNS mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}
