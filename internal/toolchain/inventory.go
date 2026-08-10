package toolchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/akimisaka/aor/pkg/contracts"
)

const ManifestName = "toolchain.json"

var ErrInvalidInventory = errors.New("invalid toolchain inventory")

type Executable struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type InstalledTool struct {
	SchemaVersion int                         `json:"schemaVersion"`
	ID            string                      `json:"id"`
	Kind          contracts.ToolchainKind     `json:"kind"`
	Name          string                      `json:"name"`
	Version       string                      `json:"version"`
	Platform      contracts.ExecutionPlatform `json:"platform"`
	Architecture  string                      `json:"architecture"`
	Languages     []string                    `json:"languages"`
	BinDirs       []string                    `json:"binDirs"`
	Executables   []Executable                `json:"executables"`
}

type Inventory struct {
	Tools []InstalledTool `json:"tools"`
}

type Source interface {
	Snapshot(context.Context) (Inventory, error)
}

type Resolver interface {
	Source
	Resolve(context.Context, []string) ([]InstalledTool, error)
	Root() string
}

type Filesystem struct {
	root string
}

func NewFilesystem(root string) (*Filesystem, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) || strings.ContainsAny(root, "\r\n\x00") {
		return nil, ErrInvalidInventory
	}
	return &Filesystem{root: root}, nil
}

func (filesystem *Filesystem) Root() string {
	if filesystem == nil {
		return ""
	}
	return filesystem.root
}

func (filesystem *Filesystem) Snapshot(ctx context.Context) (Inventory, error) {
	if filesystem == nil || ctx == nil {
		return Inventory{}, ErrInvalidInventory
	}
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	entries, err := os.ReadDir(filesystem.root)
	if errors.Is(err, os.ErrNotExist) {
		return Inventory{Tools: []InstalledTool{}}, nil
	}
	if err != nil {
		return Inventory{}, fmt.Errorf("%w: %v", ErrInvalidInventory, err)
	}
	tools := make([]InstalledTool, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return Inventory{}, err
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		manifestPath := filepath.Join(filesystem.root, entry.Name(), ManifestName)
		content, readErr := os.ReadFile(manifestPath)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return Inventory{}, fmt.Errorf("%w: %v", ErrInvalidInventory, readErr)
		}
		tool, decodeErr := decodeManifest(content)
		if decodeErr != nil || tool.ID != entry.Name() || validateInstalledTool(filesystem.root, tool) != nil {
			return Inventory{}, ErrInvalidInventory
		}
		tools = append(tools, cloneInstalledTool(tool))
	}
	sort.Slice(tools, func(left, right int) bool { return tools[left].ID < tools[right].ID })
	return Inventory{Tools: tools}, nil
}

func (filesystem *Filesystem) Resolve(ctx context.Context, ids []string) ([]InstalledTool, error) {
	if len(ids) == 0 {
		return nil, ErrInvalidInventory
	}
	inventory, err := filesystem.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]InstalledTool, len(inventory.Tools))
	for _, tool := range inventory.Tools {
		byID[tool.ID] = tool
	}
	resolved := make([]InstalledTool, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		tool, found := byID[id]
		if !found {
			return nil, ErrInvalidInventory
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, ErrInvalidInventory
		}
		seen[id] = struct{}{}
		resolved = append(resolved, cloneInstalledTool(tool))
	}
	return resolved, nil
}

func ValidateSelection(inventory Inventory, selection contracts.GoalToolchain) error {
	if err := selection.Validate(); err != nil {
		return err
	}
	byID := make(map[string]InstalledTool, len(inventory.Tools))
	for _, tool := range inventory.Tools {
		byID[tool.ID] = tool
	}
	for _, selected := range selection.Tools {
		if selected.Source == contracts.ToolchainInstallRequired {
			for _, installed := range inventory.Tools {
				if installed.Kind == selected.Kind && installed.Name == selected.Name && installed.Version == selected.Version && installed.Platform == selected.Platform && installed.Architecture == selected.Architecture {
					return ErrInvalidInventory
				}
			}
			continue
		}
		installed, found := byID[selected.InventoryID]
		if !found || installed.Kind != selected.Kind || installed.Name != selected.Name || installed.Version != selected.Version || installed.Platform != selected.Platform || installed.Architecture != selected.Architecture {
			return ErrInvalidInventory
		}
	}
	return nil
}

func ValidateResolved(tools []InstalledTool, pinned []contracts.VersionedTool) error {
	if len(tools) == 0 || len(tools) != len(pinned) {
		return ErrInvalidInventory
	}
	for index, installed := range tools {
		selected := pinned[index]
		if selected.Source != contracts.ToolchainInstalled || installed.ID != selected.InventoryID || installed.Kind != selected.Kind || installed.Name != selected.Name || installed.Version != selected.Version || installed.Platform != selected.Platform || installed.Architecture != selected.Architecture {
			return ErrInvalidInventory
		}
	}
	return nil
}

func BinPaths(root string, tools []InstalledTool) ([]string, error) {
	paths := make([]string, 0)
	for _, tool := range tools {
		for _, relative := range tool.BinDirs {
			path, err := containedPath(root, filepath.Join(tool.ID, relative))
			if err != nil {
				return nil, ErrInvalidInventory
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func decodeManifest(content []byte) (InstalledTool, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var tool InstalledTool
	if err := decoder.Decode(&tool); err != nil {
		return InstalledTool{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return InstalledTool{}, ErrInvalidInventory
	}
	return tool, nil
}

func validateInstalledTool(root string, tool InstalledTool) error {
	if tool.SchemaVersion != 1 || !safeToken(tool.ID, 128) || !safeText(tool.Name, 128) || !exactText(tool.Version, 256) || !safeToken(tool.Architecture, 128) || len(tool.Languages) == 0 || len(tool.BinDirs) == 0 || len(tool.Executables) == 0 {
		return ErrInvalidInventory
	}
	switch tool.Kind {
	case contracts.ToolchainCompiler, contracts.ToolchainRuntime, contracts.ToolchainSDK, contracts.ToolchainBuild, contracts.ToolchainInterop, contracts.ToolchainTest:
	default:
		return ErrInvalidInventory
	}
	if tool.Platform != contracts.PlatformLinux && tool.Platform != contracts.PlatformWindows {
		return ErrInvalidInventory
	}
	seenLanguages := make(map[string]struct{}, len(tool.Languages))
	for _, language := range tool.Languages {
		if !safeText(language, 128) {
			return ErrInvalidInventory
		}
		key := strings.ToLower(language)
		if _, duplicate := seenLanguages[key]; duplicate {
			return ErrInvalidInventory
		}
		seenLanguages[key] = struct{}{}
	}
	seenBins := make(map[string]struct{}, len(tool.BinDirs))
	for _, relative := range tool.BinDirs {
		path, err := containedPath(root, filepath.Join(tool.ID, relative))
		if err != nil {
			return ErrInvalidInventory
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return ErrInvalidInventory
		}
		if _, duplicate := seenBins[relative]; duplicate {
			return ErrInvalidInventory
		}
		seenBins[relative] = struct{}{}
	}
	seenExecutables := make(map[string]struct{}, len(tool.Executables))
	for _, executable := range tool.Executables {
		if !safeToken(executable.Name, 128) {
			return ErrInvalidInventory
		}
		path, err := containedPath(root, filepath.Join(tool.ID, executable.Path))
		if err != nil {
			return ErrInvalidInventory
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || tool.Platform == contracts.PlatformLinux && info.Mode().Perm()&0o111 == 0 {
			return ErrInvalidInventory
		}
		if _, duplicate := seenExecutables[executable.Name]; duplicate {
			return ErrInvalidInventory
		}
		seenExecutables[executable.Name] = struct{}{}
	}
	return nil
}

func containedPath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.ContainsAny(relative, "\r\n\x00") {
		return "", ErrInvalidInventory
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrInvalidInventory
	}
	path := filepath.Join(root, clean)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	relativeResolved, err := filepath.Rel(root, resolved)
	if err != nil || relativeResolved == ".." || strings.HasPrefix(relativeResolved, ".."+string(filepath.Separator)) {
		return "", ErrInvalidInventory
	}
	return resolved, nil
}

func safeToken(value string, maximum int) bool {
	if !safeText(value, maximum) || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func exactText(value string, maximum int) bool {
	if !safeText(value, maximum) || strings.ContainsAny(value, "*?<>^~|,") || strings.Contains(value, " - ") {
		return false
	}
	switch strings.ToLower(value) {
	case "latest", "stable", "current", "default", "nightly", "next", "head", "main", "master", "dev", "snapshot", "preview":
		return false
	default:
		segments := strings.Fields(strings.NewReplacer(".", " ", "-", " ", "_", " ", "+", " ").Replace(strings.ToLower(value)))
		for _, segment := range segments {
			if segment == "x" {
				return false
			}
		}
		return true
	}
}

func cloneInstalledTool(tool InstalledTool) InstalledTool {
	tool.Languages = append([]string(nil), tool.Languages...)
	tool.BinDirs = append([]string(nil), tool.BinDirs...)
	tool.Executables = append([]Executable(nil), tool.Executables...)
	return tool
}
