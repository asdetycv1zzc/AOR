package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/version"
	aorsdk "github.com/akimisaka/aor/sdk/go/aor"
)

const (
	defaultServer      = "https://127.0.0.1:8443"
	defaultTimeout     = 30 * time.Second
	maximumTimeout     = 5 * time.Minute
	maximumTokenBytes  = 64 << 10
	maximumRequestBody = 1 << 20
	maximumResponse    = 8 << 20
)

// Config supplies process boundaries so the CLI can be exercised without
// persistent credential storage or global process mutation.
type Config struct {
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	LookupEnv  func(string) (string, bool)
	HTTPClient *http.Client
}

type commandError struct {
	code    string
	message string
	usage   bool
}

func (err *commandError) Error() string { return err.message }

func usageError(message string) error {
	return &commandError{code: "INVALID_ARGUMENT", message: message, usage: true}
}

func runtimeError(code, message string) error {
	return &commandError{code: code, message: message}
}

// Main runs the CLI and converts failures to stable process exit codes.
func Main(ctx context.Context, args []string, config Config) int {
	config = withDefaults(config)
	err := Run(ctx, args, config)
	if err == nil {
		return 0
	}
	code := "CLI_ERROR"
	exitCode := 1
	var typed *commandError
	if errors.As(err, &typed) {
		code = typed.code
		if typed.usage {
			exitCode = 2
		}
	}
	if wantsJSON(args) {
		_ = json.NewEncoder(config.Stderr).Encode(map[string]any{
			"error": map[string]string{"code": code, "message": err.Error()},
		})
	} else {
		_, _ = fmt.Fprintln(config.Stderr, "aor:", err)
	}
	return exitCode
}

// Run parses and executes one CLI invocation.
func Run(ctx context.Context, args []string, config Config) error {
	if ctx == nil {
		return runtimeError("INVALID_CONTEXT", "context is required")
	}
	config = withDefaults(config)
	globals := globalOptions{seen: make(map[string]struct{})}
	remaining, err := parseLeadingGlobals(args, &globals)
	if err != nil {
		return err
	}
	if globals.help || len(remaining) == 0 || remaining[0] == "help" {
		_, err = io.WriteString(config.Stdout, usageText)
		return err
	}
	if remaining[0] == "version" {
		if len(remaining) != 1 {
			return usageError("version does not accept arguments")
		}
		return writeValue(config.Stdout, version.Current("aor-cli"), globals.json)
	}
	if len(remaining) < 2 {
		return usageError("expected a command group and action; run 'aor help'")
	}

	commandLength := 2
	definition, found := commandDefinitions[remaining[0]+" "+remaining[1]]
	if len(remaining) >= 3 {
		if longer, exists := commandDefinitions[remaining[0]+" "+remaining[1]+" "+remaining[2]]; exists {
			definition = longer
			found = true
			commandLength = 3
		}
	}
	if !found {
		return usageError("unknown command " + remaining[0] + " " + remaining[1])
	}
	parsed, err := parseCommandArguments(remaining[commandLength:], definition.flags, &globals)
	if err != nil {
		return err
	}
	if parsed.boolValue("help") {
		_, err = io.WriteString(config.Stdout, definition.usage+"\n")
		return err
	}
	if len(parsed.positionals) < definition.minimumPositionals || len(parsed.positionals) > definition.maximumPositionals {
		return usageError("usage: " + definition.usage)
	}

	application := &app{config: config, globals: globals}
	return definition.run(ctx, application, parsed)
}

func withDefaults(config Config) Config {
	if config.Stdin == nil {
		config.Stdin = os.Stdin
	}
	if config.Stdout == nil {
		config.Stdout = os.Stdout
	}
	if config.Stderr == nil {
		config.Stderr = os.Stderr
	}
	if config.LookupEnv == nil {
		config.LookupEnv = os.LookupEnv
	}
	return config
}

type globalOptions struct {
	server     string
	tokenEnv   string
	tokenStdin bool
	timeout    time.Duration
	json       bool
	yes        bool
	help       bool
	seen       map[string]struct{}
}

type flagKind uint8

const (
	stringFlag flagKind = iota
	boolFlag
)

type flagDefinition struct {
	kind flagKind
}

var globalFlagDefinitions = map[string]flagDefinition{
	"server":      {kind: stringFlag},
	"token-env":   {kind: stringFlag},
	"token-stdin": {kind: boolFlag},
	"timeout":     {kind: stringFlag},
	"json":        {kind: boolFlag},
	"yes":         {kind: boolFlag},
	"help":        {kind: boolFlag},
}

type parsedArguments struct {
	positionals []string
	values      map[string]string
	booleans    map[string]bool
}

func (arguments parsedArguments) value(name string) string   { return arguments.values[name] }
func (arguments parsedArguments) boolValue(name string) bool { return arguments.booleans[name] }

type commandDefinition struct {
	usage              string
	minimumPositionals int
	maximumPositionals int
	flags              map[string]flagDefinition
	run                func(context.Context, *app, parsedArguments) error
}

func parseLeadingGlobals(args []string, globals *globalOptions) ([]string, error) {
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		name, inlineValue, hasInlineValue, err := splitFlag(args[0])
		if err != nil {
			return nil, err
		}
		definition, found := globalFlagDefinitions[name]
		if !found {
			break
		}
		value, consumed, err := flagValue(name, definition.kind, inlineValue, hasInlineValue, args[1:])
		if err != nil {
			return nil, err
		}
		if err := applyGlobal(globals, name, value); err != nil {
			return nil, err
		}
		args = args[1+consumed:]
	}
	return args, nil
}

func parseCommandArguments(args []string, definitions map[string]flagDefinition, globals *globalOptions) (parsedArguments, error) {
	parsed := parsedArguments{values: make(map[string]string), booleans: make(map[string]bool)}
	seen := make(map[string]struct{})
	positionalOnly := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if positionalOnly || !strings.HasPrefix(argument, "--") {
			parsed.positionals = append(parsed.positionals, argument)
			continue
		}
		if argument == "--" {
			positionalOnly = true
			continue
		}
		name, inlineValue, hasInlineValue, err := splitFlag(argument)
		if err != nil {
			return parsed, err
		}
		definition, isCommandFlag := definitions[name]
		if !isCommandFlag {
			definition, isCommandFlag = globalFlagDefinitions[name]
			if !isCommandFlag {
				return parsed, usageError("unknown flag --" + name)
			}
		}
		value, consumed, err := flagValue(name, definition.kind, inlineValue, hasInlineValue, args[index+1:])
		if err != nil {
			return parsed, err
		}
		index += consumed
		if _, duplicate := seen[name]; duplicate {
			return parsed, usageError("flag --" + name + " may only be specified once")
		}
		seen[name] = struct{}{}
		if _, isGlobal := globalFlagDefinitions[name]; isGlobal {
			if err := applyGlobal(globals, name, value); err != nil {
				return parsed, err
			}
		}
		if definition.kind == boolFlag {
			parsed.booleans[name] = value == "true"
		} else {
			parsed.values[name] = value
		}
	}
	return parsed, nil
}

func splitFlag(argument string) (string, string, bool, error) {
	if !strings.HasPrefix(argument, "--") || argument == "--" {
		return "", "", false, usageError("invalid flag syntax")
	}
	nameValue := strings.TrimPrefix(argument, "--")
	name, value, found := strings.Cut(nameValue, "=")
	if name == "" {
		return "", "", false, usageError("flag name is required")
	}
	return name, value, found, nil
}

func flagValue(name string, kind flagKind, inline string, hasInline bool, following []string) (string, int, error) {
	if kind == boolFlag {
		if !hasInline {
			return "true", 0, nil
		}
		value, err := strconv.ParseBool(inline)
		if err != nil {
			return "", 0, usageError("flag --" + name + " expects true or false")
		}
		return strconv.FormatBool(value), 0, nil
	}
	if hasInline {
		if inline == "" {
			return "", 0, usageError("flag --" + name + " requires a value")
		}
		return inline, 0, nil
	}
	if len(following) == 0 || following[0] == "--" {
		return "", 0, usageError("flag --" + name + " requires a value")
	}
	return following[0], 1, nil
}

func applyGlobal(globals *globalOptions, name, value string) error {
	if _, duplicate := globals.seen[name]; duplicate {
		return usageError("flag --" + name + " may only be specified once")
	}
	globals.seen[name] = struct{}{}
	switch name {
	case "server":
		globals.server = value
	case "token-env":
		if len(value) > 128 || strings.ContainsAny(value, "=\x00\r\n") {
			return usageError("--token-env is invalid")
		}
		globals.tokenEnv = value
	case "token-stdin":
		globals.tokenStdin = value == "true"
	case "timeout":
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 || timeout > maximumTimeout {
			return usageError("--timeout must be greater than zero and no more than 5m")
		}
		globals.timeout = timeout
	case "json":
		globals.json = value == "true"
	case "yes":
		globals.yes = value == "true"
	case "help":
		globals.help = value == "true"
	}
	return nil
}

func wantsJSON(args []string) bool {
	for _, argument := range args {
		if argument == "--json" || argument == "--json=true" {
			return true
		}
	}
	return false
}

type app struct {
	config  Config
	globals globalOptions
	client  *aorsdk.Client
}

func (application *app) api() (*aorsdk.Client, error) {
	if application.client != nil {
		return application.client, nil
	}
	server := application.globals.server
	if server == "" {
		if configured, found := application.config.LookupEnv("AOR_API_URL"); found && strings.TrimSpace(configured) != "" {
			server = strings.TrimSpace(configured)
		} else {
			server = defaultServer
		}
	}
	timeout := application.globals.timeout
	if timeout == 0 {
		if configured, found := application.config.LookupEnv("AOR_TIMEOUT"); found && strings.TrimSpace(configured) != "" {
			parsed, err := time.ParseDuration(strings.TrimSpace(configured))
			if err != nil || parsed <= 0 || parsed > maximumTimeout {
				return nil, runtimeError("INVALID_CONFIGURATION", "AOR_TIMEOUT must be greater than zero and no more than 5m")
			}
			timeout = parsed
		} else {
			timeout = defaultTimeout
		}
	}
	token, err := application.accessToken()
	if err != nil {
		return nil, err
	}
	httpClient := secureHTTPClient(application.config.HTTPClient, timeout)
	client, err := aorsdk.NewClient(server, httpClient, func(context.Context) (string, error) { return token, nil })
	if err != nil {
		return nil, runtimeError("INVALID_CONFIGURATION", err.Error())
	}
	application.client = client
	return client, nil
}

func (application *app) accessToken() (string, error) {
	var token string
	if application.globals.tokenStdin {
		reader := bufio.NewReader(io.LimitReader(application.config.Stdin, maximumTokenBytes+1))
		contents, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", runtimeError("CREDENTIAL_READ_FAILED", "could not read the access token from standard input")
		}
		if len(contents) > maximumTokenBytes {
			return "", runtimeError("CREDENTIAL_READ_FAILED", "the access token exceeds 64 KiB")
		}
		token = strings.TrimSpace(contents)
	} else {
		name := application.globals.tokenEnv
		if name == "" {
			name = "AOR_TOKEN"
		}
		token, _ = application.config.LookupEnv(name)
		token = strings.TrimSpace(token)
	}
	if token == "" {
		return "", runtimeError("CREDENTIAL_REQUIRED", "set AOR_TOKEN, select an environment variable with --token-env, or use --token-stdin")
	}
	if len(token) > maximumTokenBytes || !validBearerToken(token) {
		return "", runtimeError("CREDENTIAL_INVALID", "the access token is invalid")
	}
	return token, nil
}

func validBearerToken(token string) bool {
	if token == "" {
		return false
	}
	for _, character := range token {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-._~+/=", character) {
			continue
		}
		return false
	}
	return true
}

func secureHTTPClient(configured *http.Client, timeout time.Duration) *http.Client {
	client := &http.Client{}
	if configured != nil {
		*client = *configured
	}
	client.Timeout = timeout
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if configured != nil {
		if candidate, ok := configured.Transport.(*http.Transport); ok && candidate != nil {
			transport = candidate.Clone()
		} else if configured.Transport != nil {
			client.Transport = configured.Transport
			transport = nil
		}
	}
	if transport != nil {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if transport.TLSClientConfig != nil {
			tlsConfig = transport.TLSClientConfig.Clone()
			if tlsConfig.MinVersion < tls.VersionTLS12 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
		}
		transport.TLSClientConfig = tlsConfig
		client.Transport = transport
	}
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && (request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Host, via[0].URL.Host)) {
			return errors.New("cross-origin or non-HTTPS redirect rejected")
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		return nil
	}
	return client
}

func writeValue(destination io.Writer, value any, compact bool) error {
	encoder := json.NewEncoder(destination)
	encoder.SetEscapeHTML(false)
	if !compact {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(value)
}

const usageText = `Usage: aor [global flags] <group> <action> [arguments]

Global flags:
  --server URL          AOR HTTPS API URL (default: AOR_API_URL or https://127.0.0.1:8443)
  --token-env NAME      environment variable containing the access token (default: AOR_TOKEN)
  --token-stdin         read the access token once from standard input
  --timeout DURATION    total request timeout, up to 5m (default: 30s)
  --json                emit compact JSON
  --yes                 approve a destructive action without an interactive prompt

Commands:
  aor project create --name NAME --goal-agent-count 1|2 --data-classification CLASS
  aor project status <id>
  aor project pause|resume|abort <id>
  aor goal send <id> --file request.md
  aor goal diff <id> --from VERSION --to VERSION
  aor goal approve <id> --version VERSION --sha256 DIGEST
  aor task list <id>
  aor task show <id> <task>
  aor task decide <id> <task> --decision DECISION
  aor audit show <audit-id> --project PROJECT --task TASK
  aor artifact download <uri> --project PROJECT
  aor knowledge refs <project> --query QUERY
  aor budget show <project>
  aor admin doctor
  aor admin policy test [--file request.json]
  aor admin sandbox probe [--file request.json]
`
