package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/akimisaka/aor/internal/platformaudit"
)

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: aor-platform-audit generate --input case.json --output report.json | compare --linux report.json --windows report.json"))
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(os.Args[2:])
	case "compare":
		err = compare(os.Args[2:])
	default:
		err = errors.New("unknown command: " + os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func generate(arguments []string) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	inputPath := flags.String("input", "", "platform audit case")
	outputPath := flags.String("output", "", "platform audit report")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *inputPath == "" || *outputPath == "" {
		return errors.New("generate requires --input and --output")
	}
	var testCase platformaudit.Case
	if err := readJSON(*inputPath, &testCase); err != nil {
		return err
	}
	report, err := platformaudit.GenerateNative(context.Background(), testCase)
	if err != nil {
		return err
	}
	return writeJSON(*outputPath, report)
}

func compare(arguments []string) error {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	linuxPath := flags.String("linux", "", "Linux arm64 report")
	windowsPath := flags.String("windows", "", "Windows amd64 report")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *linuxPath == "" || *windowsPath == "" {
		return errors.New("compare requires --linux and --windows")
	}
	var linux, windows platformaudit.Report
	if err := readJSON(*linuxPath, &linux); err != nil {
		return err
	}
	if err := readJSON(*windowsPath, &windows); err != nil {
		return err
	}
	return platformaudit.Compare(linux, windows)
}

func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 8<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode %s: trailing JSON", path)
	}
	return nil
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o600)
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
