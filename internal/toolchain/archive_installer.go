package toolchain

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/klauspost/compress/zstd"
)

var (
	ErrUnsupportedArchive   = errors.New("unsupported toolchain archive")
	ErrUnsupportedTool      = errors.New("unsupported portable toolchain")
	ErrArchiveLimit         = errors.New("toolchain archive limit exceeded")
	ErrToolchainConflict    = errors.New("toolchain inventory ID conflict")
	ErrToolchainDigest      = errors.New("toolchain archive SHA-256 mismatch")
	ErrToolchainVersion     = errors.New("toolchain version probe mismatch")
	ErrToolchainNotPortable = errors.New("toolchain archive is not a self-contained portable distribution")
)

const (
	defaultDownloadLimit = int64(4 << 30)
	defaultExtractLimit  = int64(8 << 30)
	defaultFileLimit     = 200000
	defaultProbeLimit    = int64(1 << 20)
)

type ArchiveInstallerConfig struct {
	ToolchainRoot    string
	WorkRoot         string
	HTTPClient       *http.Client
	MaxDownloadBytes int64
	MaxExtractBytes  int64
	MaxFiles         int
	Clock            func() time.Time
	Prober           ExecutableProber
}

type ArchiveInstaller struct {
	toolchainRoot    string
	workRoot         string
	httpClient       *http.Client
	maxDownloadBytes int64
	maxExtractBytes  int64
	maxFiles         int
	clock            func() time.Time
	prober           ExecutableProber
}

type toolProfile struct {
	names       []string
	executables []profileExecutable
}

type profileExecutable struct {
	name        string
	paths       []string
	versionArgs []string
}

var portableToolProfiles = []toolProfile{
	{names: []string{"go", "golang"}, executables: []profileExecutable{{name: "go", paths: []string{"bin/go", "go/bin/go"}, versionArgs: []string{"version"}}}},
	{names: []string{"node", "node.js", "nodejs"}, executables: []profileExecutable{{name: "node", paths: []string{"bin/node", "node/bin/node"}, versionArgs: []string{"--version"}}}},
	{names: []string{"dotnet", ".net", ".net sdk", "dotnet sdk"}, executables: []profileExecutable{{name: "dotnet", paths: []string{"dotnet", "bin/dotnet"}, versionArgs: []string{"--version"}}}},
	{names: []string{"jdk", "java", "openjdk", "java sdk"}, executables: []profileExecutable{{name: "java", paths: []string{"bin/java", "Contents/Home/bin/java"}, versionArgs: []string{"--version"}}, {name: "javac", paths: []string{"bin/javac", "Contents/Home/bin/javac"}, versionArgs: []string{"--version"}}}},
	{names: []string{"python", "python3", "cpython"}, executables: []profileExecutable{{name: "python3", paths: []string{"bin/python3", "bin/python"}, versionArgs: []string{"--version"}}}},
	{names: []string{"rust", "rustc", "rust toolchain"}, executables: []profileExecutable{{name: "rustc", paths: []string{"bin/rustc"}, versionArgs: []string{"--version"}}, {name: "cargo", paths: []string{"bin/cargo"}, versionArgs: []string{"--version"}}}},
	{names: []string{"perl"}, executables: []profileExecutable{{name: "perl", paths: []string{"bin/perl"}, versionArgs: []string{"-v"}}}},
	{names: []string{"ghc", "haskell", "glasgow haskell compiler"}, executables: []profileExecutable{{name: "ghc", paths: []string{"bin/ghc"}, versionArgs: []string{"--numeric-version"}}}},
	{names: []string{"freepascal", "free pascal", "fpc", "pascal"}, executables: []profileExecutable{{name: "fpc", paths: []string{"bin/fpc"}, versionArgs: []string{"-iV"}}}},
	{names: []string{"nasm"}, executables: []profileExecutable{{name: "nasm", paths: []string{"bin/nasm", "nasm"}, versionArgs: []string{"-v"}}}},
	{names: []string{"yasm"}, executables: []profileExecutable{{name: "yasm", paths: []string{"bin/yasm", "yasm"}, versionArgs: []string{"--version"}}}},
}

func NewArchiveInstaller(config ArchiveInstallerConfig) (*ArchiveInstaller, error) {
	if !validInstallerRoot(config.ToolchainRoot) || !validInstallerRoot(config.WorkRoot) || filepath.Clean(config.ToolchainRoot) == filepath.Clean(config.WorkRoot) {
		return nil, ErrInvalidInventory
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Minute, CheckRedirect: httpsRedirectPolicy}
	}
	downloadLimit := config.MaxDownloadBytes
	if downloadLimit <= 0 {
		downloadLimit = defaultDownloadLimit
	}
	extractLimit := config.MaxExtractBytes
	if extractLimit <= 0 {
		extractLimit = defaultExtractLimit
	}
	fileLimit := config.MaxFiles
	if fileLimit <= 0 {
		fileLimit = defaultFileLimit
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	prober := config.Prober
	if prober == nil {
		prober = LocalExecutableProber{}
	}
	return &ArchiveInstaller{
		toolchainRoot: filepath.Clean(config.ToolchainRoot), workRoot: filepath.Clean(config.WorkRoot), httpClient: client,
		maxDownloadBytes: downloadLimit, maxExtractBytes: extractLimit, maxFiles: fileLimit, clock: clock, prober: prober,
	}, nil
}

func (installer *ArchiveInstaller) Install(ctx context.Context, tool contracts.VersionedTool, languages []string) (InstalledTool, error) {
	if installer == nil || ctx == nil || !tool.ReadyToProvision() || tool.Install == nil || tool.Install.Method != contracts.ToolchainInstallUserArchive ||
		!SupportsPortableArchive(tool) {
		return InstalledTool{}, ErrUnsupportedTool
	}
	if err := validateVersionedToolContract(tool); err != nil {
		return InstalledTool{}, ErrUnsupportedTool
	}
	profile, found := profileFor(tool.Name)
	if !found {
		return InstalledTool{}, ErrUnsupportedTool
	}
	languages, err := normalizeLanguages(languages, tool.Name)
	if err != nil {
		return InstalledTool{}, err
	}
	if err := os.MkdirAll(installer.toolchainRoot, 0o755); err != nil {
		return InstalledTool{}, err
	}
	if err := os.MkdirAll(installer.workRoot, 0o700); err != nil {
		return InstalledTool{}, err
	}
	jobRoot, err := os.MkdirTemp(installer.workRoot, "archive-")
	if err != nil {
		return InstalledTool{}, err
	}
	defer os.RemoveAll(jobRoot)
	archivePath := filepath.Join(jobRoot, "source.archive")
	digest, err := installer.download(ctx, tool.Install.DownloadURL, archivePath)
	if err != nil {
		return InstalledTool{}, err
	}
	if "sha256:"+digest != tool.Install.SourceSHA256 {
		return InstalledTool{}, ErrToolchainDigest
	}
	extractRoot := filepath.Join(jobRoot, "extracted")
	if err := os.Mkdir(extractRoot, 0o700); err != nil {
		return InstalledTool{}, err
	}
	if err := installer.extract(ctx, archivePath, tool.Install.DownloadURL, extractRoot); err != nil {
		return InstalledTool{}, err
	}
	payloadRoot, err := normalizedPayloadRoot(extractRoot)
	if err != nil {
		return InstalledTool{}, err
	}
	executables, binDirs, err := locateExecutables(payloadRoot, profile)
	if err != nil {
		return InstalledTool{}, err
	}
	if err := installer.prober.Probe(ctx, probeRequest(payloadRoot, executables, profile, tool.Version)); err != nil {
		return InstalledTool{}, err
	}
	id := inventoryID(tool, digest)
	manifest := InstalledTool{
		SchemaVersion: 1, ID: id, Kind: tool.Kind, Name: tool.Name, Version: tool.Version, Platform: tool.Platform,
		Architecture: canonicalArchitecture(tool.Architecture), Languages: languages, BinDirs: binDirs, Executables: executables,
		Provenance: &InstallationProvenance{Method: contracts.ToolchainInstallUserArchive, SourceURL: tool.Install.DownloadURL,
			SourceSHA256: "sha256:" + digest, EvidenceRef: tool.Install.EvidenceRef, InstalledAt: installer.clock().UTC().Format(time.RFC3339Nano)},
	}
	return installer.publish(ctx, payloadRoot, manifest, profile)
}

func validateVersionedToolContract(tool contracts.VersionedTool) error {
	selection := contracts.GoalToolchain{
		Languages: []contracts.LanguageRequirement{{Name: tool.Name, Version: tool.Version}},
		Tools:     []contracts.VersionedTool{tool},
	}
	return selection.Validate()
}

func validInstallerRoot(root string) bool {
	return root != "" && filepath.IsAbs(root) && filepath.Clean(root) == root && root != string(filepath.Separator) && !strings.ContainsAny(root, "\r\n\x00")
}

func httpsRedirectPolicy(request *http.Request, previous []*http.Request) error {
	if request.URL.Scheme != "https" || len(previous) >= 10 {
		return errors.New("toolchain archive redirect must remain HTTPS")
	}
	return nil
}

func (installer *ArchiveInstaller) download(ctx context.Context, rawURL, destination string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", ErrUnsupportedArchive
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	response, err := installer.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("toolchain archive download returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > installer.maxDownloadBytes {
		return "", ErrArchiveLimit
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, installer.maxDownloadBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written > installer.maxDownloadBytes {
		return "", ErrArchiveLimit
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (installer *ArchiveInstaller) extract(ctx context.Context, archivePath, rawURL, destination string) error {
	kind := archiveKind(rawURL)
	switch kind {
	case "zip":
		return installer.extractZip(ctx, archivePath, destination)
	case "tar", "tar.gz", "tar.xz", "tar.zst":
		reader, closeReader, err := tarStream(ctx, archivePath, kind, installer.maxExtractBytes)
		if err != nil {
			return err
		}
		defer closeReader()
		return installer.extractTar(ctx, reader, destination)
	default:
		return ErrUnsupportedArchive
	}
}

func archiveKind(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := strings.ToLower(parsed.Path)
	for _, suffix := range []struct{ suffix, kind string }{{".tar.gz", "tar.gz"}, {".tgz", "tar.gz"}, {".tar.xz", "tar.xz"}, {".txz", "tar.xz"}, {".tar.zst", "tar.zst"}, {".tzst", "tar.zst"}, {".zip", "zip"}, {".tar", "tar"}} {
		if strings.HasSuffix(path, suffix.suffix) {
			return suffix.kind
		}
	}
	return ""
}

func tarStream(ctx context.Context, path, kind string, maximumDecodedBytes int64) (io.Reader, func(), error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	closeFile := func() { _ = file.Close() }
	switch kind {
	case "tar":
		return file, closeFile, nil
	case "tar.gz":
		reader, err := gzip.NewReader(file)
		if err != nil {
			closeFile()
			return nil, nil, err
		}
		return reader, func() { _ = reader.Close(); closeFile() }, nil
	case "tar.zst":
		reader, err := zstd.NewReader(file, zstd.WithDecoderMaxMemory(uint64(maximumDecodedBytes)))
		if err != nil {
			closeFile()
			return nil, nil, err
		}
		return reader, func() { reader.Close(); closeFile() }, nil
	case "tar.xz":
		if _, err := exec.LookPath("xz"); err != nil {
			closeFile()
			return nil, nil, fmt.Errorf("%w: xz decompressor unavailable", ErrUnsupportedArchive)
		}
		command := exec.CommandContext(ctx, "xz", "-dc", "--", path)
		stdout, err := command.StdoutPipe()
		if err != nil {
			closeFile()
			return nil, nil, err
		}
		if err := command.Start(); err != nil {
			closeFile()
			return nil, nil, err
		}
		closeFile()
		reader := &commandReader{reader: stdout, command: command}
		return reader, func() { _ = reader.Close() }, nil
	default:
		closeFile()
		return nil, nil, ErrUnsupportedArchive
	}
}

type commandReader struct {
	reader  io.ReadCloser
	command *exec.Cmd
	done    bool
}

func (reader *commandReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	if errors.Is(err, io.EOF) && !reader.done {
		reader.done = true
		if waitErr := reader.command.Wait(); waitErr != nil {
			return read, waitErr
		}
	}
	return read, err
}

func (reader *commandReader) Close() error {
	closeErr := reader.reader.Close()
	if !reader.done {
		reader.done = true
		waitErr := reader.command.Wait()
		if closeErr == nil {
			closeErr = waitErr
		}
	}
	return closeErr
}

func (installer *ArchiveInstaller) extractTar(ctx context.Context, input io.Reader, destination string) error {
	reader := tar.NewReader(input)
	state := extractionState{maxBytes: installer.maxExtractBytes, maxFiles: installer.maxFiles}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := state.addHeader(header.Size); err != nil {
			return err
		}
		path, err := archiveDestination(destination, header.Name)
		if err != nil {
			return err
		}
		if err := rejectSymlinkParent(destination, path); err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, sanitizedDirMode(header.FileInfo().Mode())); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := writeArchiveFile(path, reader, header.Size, header.FileInfo().Mode()); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := createArchiveSymlink(destination, path, header.Linkname); err != nil {
				return err
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		default:
			return ErrUnsupportedArchive
		}
	}
}

func (installer *ArchiveInstaller) extractZip(ctx context.Context, archivePath, destination string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	state := extractionState{maxBytes: installer.maxExtractBytes, maxFiles: installer.maxFiles}
	for _, entry := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.UncompressedSize64 > uint64(^uint64(0)>>1) || state.addHeader(int64(entry.UncompressedSize64)) != nil {
			return ErrArchiveLimit
		}
		path, err := archiveDestination(destination, entry.Name)
		if err != nil {
			return err
		}
		if err := rejectSymlinkParent(destination, path); err != nil {
			return err
		}
		mode := entry.Mode()
		if mode.IsDir() {
			if err := os.MkdirAll(path, sanitizedDirMode(mode)); err != nil {
				return err
			}
			continue
		}
		if mode&os.ModeType != 0 {
			return ErrUnsupportedArchive
		}
		input, err := entry.Open()
		if err != nil {
			return err
		}
		err = writeArchiveFile(path, input, int64(entry.UncompressedSize64), mode)
		_ = input.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type extractionState struct {
	bytes, maxBytes int64
	files, maxFiles int
}

func (state *extractionState) addHeader(size int64) error {
	if size < 0 || state.files >= state.maxFiles || size > state.maxBytes-state.bytes {
		return ErrArchiveLimit
	}
	state.files++
	state.bytes += size
	return nil
}

func archiveDestination(root, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || strings.ContainsAny(name, "\x00\r\n") {
		return "", ErrUnsupportedArchive
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrUnsupportedArchive
	}
	return filepath.Join(root, clean), nil
}

func rejectSymlinkParent(root, path string) error {
	parent := filepath.Dir(path)
	relative, err := filepath.Rel(root, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrUnsupportedArchive
	}
	current := root
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrUnsupportedArchive
		}
	}
	return nil
}

func writeArchiveFile(path string, input io.Reader, size int64, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, sanitizedFileMode(mode))
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(input, size+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != size {
		return ErrUnsupportedArchive
	}
	return nil
}

func createArchiveSymlink(root, path, target string) error {
	if target == "" || filepath.IsAbs(target) || strings.ContainsAny(target, "\x00\r\n") {
		return ErrUnsupportedArchive
	}
	resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(target)))
	relative, err := filepath.Rel(root, resolvedTarget)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrUnsupportedArchive
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := rejectSymlinkParent(root, path); err != nil {
		return err
	}
	return os.Symlink(filepath.FromSlash(target), path)
}

func sanitizedDirMode(mode os.FileMode) os.FileMode {
	return 0o755 | mode.Perm()&0o022
}

func sanitizedFileMode(mode os.FileMode) os.FileMode {
	return 0o644 | mode.Perm()&0o111
}

func normalizedPayloadRoot(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) == 0 {
		return "", ErrUnsupportedArchive
	}
	if len(entries) == 1 && entries[0].IsDir() && entries[0].Type()&os.ModeSymlink == 0 {
		return filepath.Join(root, entries[0].Name()), nil
	}
	return root, nil
}

func profileFor(name string) (toolProfile, bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for _, profile := range portableToolProfiles {
		for _, candidate := range profile.names {
			if normalized == candidate {
				return profile, true
			}
		}
	}
	return toolProfile{}, false
}

func SupportsPortableArchive(tool contracts.VersionedTool) bool {
	if tool.Platform != contracts.PlatformLinux || contracts.IsGCCTool(tool) || !architectureMatches(tool.Architecture) {
		return false
	}
	_, found := profileFor(tool.Name)
	return found
}

func locateExecutables(root string, profile toolProfile) ([]Executable, []string, error) {
	executables := make([]Executable, 0, len(profile.executables))
	binSet := make(map[string]struct{})
	for _, expected := range profile.executables {
		var found string
		for _, candidate := range expected.paths {
			path := filepath.Join(root, filepath.FromSlash(candidate))
			info, err := os.Stat(path)
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				found = filepath.ToSlash(candidate)
				break
			}
		}
		if found == "" {
			return nil, nil, ErrToolchainNotPortable
		}
		executables = append(executables, Executable{Name: expected.name, Path: found})
		directory := filepath.ToSlash(filepath.Dir(filepath.FromSlash(found)))
		if directory == "." {
			directory = "."
		}
		binSet[directory] = struct{}{}
	}
	binDirs := make([]string, 0, len(binSet))
	for directory := range binSet {
		binDirs = append(binDirs, directory)
	}
	sort.Strings(binDirs)
	return executables, binDirs, nil
}

func probeExecutables(ctx context.Context, root string, executables []Executable, profile toolProfile, version string) error {
	for index, executable := range executables {
		path := filepath.Join(root, filepath.FromSlash(executable.Path))
		command := exec.CommandContext(ctx, path, profile.executables[index].versionArgs...)
		command.Dir = root
		command.Env = portableEnvironment(root)
		output, err := limitedCombinedOutput(command, defaultProbeLimit)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrToolchainNotPortable, executable.Name, err)
		}
		if !exactVersionInOutput(string(output), version) {
			return fmt.Errorf("%w: %s", ErrToolchainVersion, executable.Name)
		}
	}
	return nil
}

func portableEnvironment(root string) []string {
	paths := []string{filepath.Join(root, "bin")}
	if systemPath := os.Getenv("PATH"); systemPath != "" {
		paths = append(paths, systemPath)
	}
	return []string{"HOME=" + root, "LANG=C", "LC_ALL=C", "PATH=" + strings.Join(paths, string(os.PathListSeparator))}
}

func limitedCombinedOutput(command *exec.Cmd, maximum int64) ([]byte, error) {
	output := &limitedOutput{remaining: maximum}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		return nil, err
	}
	waitErr := command.Wait()
	if output.exceeded {
		return nil, ErrArchiveLimit
	}
	return output.content, waitErr
}

type limitedOutput struct {
	content   []byte
	remaining int64
	exceeded  bool
}

func (output *limitedOutput) Write(content []byte) (int, error) {
	originalLength := len(content)
	if int64(len(content)) > output.remaining {
		content = content[:output.remaining]
		output.exceeded = true
	}
	output.content = append(output.content, content...)
	output.remaining -= int64(len(content))
	return originalLength, nil
}

func exactVersionInOutput(output, version string) bool {
	version = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(version), "v"))
	if version == "" {
		return false
	}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		token := strings.Trim(scanner.Text(), "vV()[]{}:,;=\"'")
		if token == version || strings.TrimPrefix(token, "go") == version {
			return true
		}
	}
	return false
}

func normalizeLanguages(languages []string, fallback string) ([]string, error) {
	if len(languages) == 0 {
		languages = []string{fallback}
	}
	seen := make(map[string]struct{}, len(languages))
	result := make([]string, 0, len(languages))
	for _, language := range languages {
		language = strings.TrimSpace(language)
		if !safeText(language, 128) {
			return nil, ErrInvalidInventory
		}
		key := strings.ToLower(language)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, language)
	}
	sort.Strings(result)
	return result, nil
}

func architectureMatches(requested string) bool {
	return canonicalArchitecture(requested) == canonicalArchitecture(runtime.GOARCH)
}

func canonicalArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x86_64", "x64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func inventoryID(tool contracts.VersionedTool, digest string) string {
	base := strings.ToLower(tool.Name + "-" + tool.Version + "-linux-" + canonicalArchitecture(tool.Architecture))
	var builder strings.Builder
	for _, character := range base {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else if builder.Len() > 0 {
			current := builder.String()
			if current[len(current)-1] != '-' {
				builder.WriteByte('-')
			}
		}
	}
	name := strings.Trim(builder.String(), "-")
	if len(name) > 96 {
		name = name[:96]
	}
	return name + "-" + digest[:16]
}

func (installer *ArchiveInstaller) publish(ctx context.Context, payloadRoot string, manifest InstalledTool, profile toolProfile) (InstalledTool, error) {
	finalPath := filepath.Join(installer.toolchainRoot, manifest.ID)
	if existing, err := readExistingTool(ctx, installer.toolchainRoot, manifest.ID); err == nil {
		if sameInstalledArtifact(existing, manifest) {
			return existing, nil
		}
		return InstalledTool{}, ErrToolchainConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return InstalledTool{}, err
	}
	stagingParent, err := os.MkdirTemp(installer.toolchainRoot, ".staging-")
	if err != nil {
		return InstalledTool{}, err
	}
	defer os.RemoveAll(stagingParent)
	stagingPath := filepath.Join(stagingParent, manifest.ID)
	if err := copyTree(payloadRoot, stagingPath); err != nil {
		return InstalledTool{}, err
	}
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return InstalledTool{}, err
	}
	content = append(content, '\n')
	if err := os.WriteFile(filepath.Join(stagingPath, ManifestName), content, 0o644); err != nil {
		return InstalledTool{}, err
	}
	stagingInventory, err := NewFilesystem(stagingParent)
	if err != nil {
		return InstalledTool{}, err
	}
	snapshot, err := stagingInventory.Snapshot(ctx)
	if err != nil || len(snapshot.Tools) != 1 {
		return InstalledTool{}, ErrInvalidInventory
	}
	if err := installer.prober.Probe(ctx, probeRequest(stagingPath, manifest.Executables, profile, manifest.Version)); err != nil {
		return InstalledTool{}, err
	}
	if err := os.Rename(stagingPath, finalPath); err != nil {
		existing, readErr := readExistingTool(ctx, installer.toolchainRoot, manifest.ID)
		if readErr == nil {
			if sameInstalledArtifact(existing, manifest) {
				return existing, nil
			}
			return InstalledTool{}, ErrToolchainConflict
		}
		return InstalledTool{}, err
	}
	return cloneInstalledTool(manifest), nil
}

func readExistingTool(ctx context.Context, root, id string) (InstalledTool, error) {
	content, err := os.ReadFile(filepath.Join(root, id, ManifestName))
	if err != nil {
		return InstalledTool{}, err
	}
	tool, err := decodeManifest(content)
	if err != nil || tool.ID != id || validateInstalledTool(root, tool) != nil {
		return InstalledTool{}, ErrInvalidInventory
	}
	if err := ctx.Err(); err != nil {
		return InstalledTool{}, err
	}
	return tool, nil
}

func sameInstalledArtifact(left, right InstalledTool) bool {
	if left.Provenance != nil && right.Provenance != nil {
		left.Provenance.InstalledAt = ""
		right.Provenance.InstalledAt = ""
	}
	leftContent, leftErr := json.Marshal(left)
	rightContent, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftContent) == string(rightContent)
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(target, sanitizedDirMode(info.Mode()))
		}
		if entry.Type()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return createArchiveSymlink(destination, target, link)
		}
		if !info.Mode().IsRegular() {
			return ErrUnsupportedArchive
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		err = writeArchiveFile(target, input, info.Size(), info.Mode())
		_ = input.Close()
		return err
	})
}
