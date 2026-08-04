package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	aorsdk "github.com/akimisaka/aor/sdk/go/aor"
)

var commandDefinitions = map[string]commandDefinition{
	"project create": {
		usage: "aor project create --name NAME --goal-agent-count 1|2 --data-classification CLASS --deployment-targets TARGET[,TARGET...] --budget-hard-limit-minor AMOUNT --budget-soft-limit-minor AMOUNT --budget-currency CURRENCY [--idempotency-key KEY]",
		flags: map[string]flagDefinition{
			"name": {kind: stringFlag}, "goal-agent-count": {kind: stringFlag}, "data-classification": {kind: stringFlag},
			"deployment-targets": {kind: stringFlag}, "budget-hard-limit-minor": {kind: stringFlag}, "budget-soft-limit-minor": {kind: stringFlag},
			"budget-currency": {kind: stringFlag}, "idempotency-key": {kind: stringFlag},
		},
		run: createProject,
	},
	"project status": {usage: "aor project status <id>", minimumPositionals: 1, maximumPositionals: 1, run: projectStatus},
	"project pause": {
		usage: "aor project pause <id> [--idempotency-key KEY]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"idempotency-key": {kind: stringFlag}}, run: pauseProject,
	},
	"project resume": {
		usage: "aor project resume <id> [--idempotency-key KEY]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"idempotency-key": {kind: stringFlag}}, run: resumeProject,
	},
	"project abort": {
		usage: "aor project abort <id> [--yes] [--idempotency-key KEY]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"idempotency-key": {kind: stringFlag}}, run: abortProject,
	},
	"goal send": {
		usage: "aor goal send <id> --file request.md [--idempotency-key KEY]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"file": {kind: stringFlag}, "idempotency-key": {kind: stringFlag}}, run: sendGoal,
	},
	"goal diff": {
		usage: "aor goal diff <id> --from VERSION --to VERSION", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"from": {kind: stringFlag}, "to": {kind: stringFlag}}, run: diffGoal,
	},
	"goal approve": {
		usage: "aor goal approve <id> --version VERSION --sha256 DIGEST [--idempotency-key KEY]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"version": {kind: stringFlag}, "sha256": {kind: stringFlag}, "idempotency-key": {kind: stringFlag}}, run: approveGoal,
	},
	"task list": {
		usage: "aor task list <project> [--cursor CURSOR]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"cursor": {kind: stringFlag}}, run: listTasks,
	},
	"task show": {usage: "aor task show <project> <task>", minimumPositionals: 2, maximumPositionals: 2, run: showTask},
	"task decide": {
		usage: "aor task decide <project> <task> --decision DECISION [--idempotency-key KEY]", minimumPositionals: 2, maximumPositionals: 2,
		flags: map[string]flagDefinition{"decision": {kind: stringFlag}, "idempotency-key": {kind: stringFlag}}, run: decideTask,
	},
	"audit show": {
		usage: "aor audit show <audit-id> [--project PROJECT --task TASK]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"project": {kind: stringFlag}, "task": {kind: stringFlag}}, run: showAudit,
	},
	"artifact download": {
		usage: "aor artifact download <artifact://sha256/digest> --project PROJECT", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"project": {kind: stringFlag}}, run: downloadArtifact,
	},
	"knowledge refs": {
		usage: "aor knowledge refs <project> --query QUERY [--idempotency-key KEY]", minimumPositionals: 1, maximumPositionals: 1,
		flags: map[string]flagDefinition{"query": {kind: stringFlag}, "idempotency-key": {kind: stringFlag}}, run: knowledgeReferences,
	},
	"budget show": {usage: "aor budget show <project>", minimumPositionals: 1, maximumPositionals: 1, run: showBudget},
	"admin doctor": {
		usage: "aor admin doctor [--file request.json] [--idempotency-key KEY]",
		flags: map[string]flagDefinition{"file": {kind: stringFlag}, "idempotency-key": {kind: stringFlag}}, run: runDoctor,
	},
	"admin policy test": {
		usage: "aor admin policy test [--file request.json] [--idempotency-key KEY]",
		flags: map[string]flagDefinition{"file": {kind: stringFlag}, "idempotency-key": {kind: stringFlag}}, run: testPolicies,
	},
	"admin sandbox probe": {
		usage: "aor admin sandbox probe [--file request.json] [--idempotency-key KEY]",
		flags: map[string]flagDefinition{"file": {kind: stringFlag}, "idempotency-key": {kind: stringFlag}}, run: probeSandboxes,
	},
}

func createProject(ctx context.Context, application *app, arguments parsedArguments) error {
	name, err := requireValue(arguments, "name")
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if len(name) > 256 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
		return usageError("--name is invalid")
	}
	count, err := strconv.Atoi(arguments.value("goal-agent-count"))
	if err != nil || count < 1 || count > 2 {
		return usageError("--goal-agent-count must be 1 or 2")
	}
	classification := strings.ToUpper(arguments.value("data-classification"))
	if !oneOf(classification, "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED") {
		return usageError("--data-classification must be PUBLIC, INTERNAL, CONFIDENTIAL, or RESTRICTED")
	}
	targetValue, err := requireValue(arguments, "deployment-targets")
	if err != nil {
		return err
	}
	targets := strings.Split(targetValue, ",")
	if len(targets) > 16 {
		return usageError("--deployment-targets accepts at most 16 comma-separated targets")
	}
	seenTargets := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target == "" || len(target) > 128 || strings.TrimSpace(target) != target || strings.ContainsAny(target, "\x00\r\n") {
			return usageError("--deployment-targets contains an invalid target")
		}
		if _, duplicate := seenTargets[target]; duplicate {
			return usageError("--deployment-targets may not contain duplicates")
		}
		seenTargets[target] = struct{}{}
	}
	hardLimit, err := requirePositiveInteger(arguments, "budget-hard-limit-minor")
	if err != nil {
		return err
	}
	softLimit, err := strconv.ParseInt(arguments.value("budget-soft-limit-minor"), 10, 64)
	if err != nil || softLimit < 0 || softLimit > hardLimit {
		return usageError("--budget-soft-limit-minor must be a non-negative integer no greater than the hard limit")
	}
	currency := strings.ToUpper(arguments.value("budget-currency"))
	if len(currency) != 3 || currency[0] < 'A' || currency[0] > 'Z' || currency[1] < 'A' || currency[1] > 'Z' || currency[2] < 'A' || currency[2] > 'Z' {
		return usageError("--budget-currency must be a three-letter currency code")
	}
	key, err := idempotencyKey(arguments)
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.CreateProject(ctx, aorsdk.RequestOptions{
		Headers: commandHeaders(key, ""),
		Body: map[string]any{
			"name": name, "goalAgentCount": count, "dataClassification": classification, "deploymentTargets": targets,
			"budget": map[string]any{"hardLimitMinor": hardLimit, "softLimitMinor": softLimit, "currency": currency},
		},
	})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func projectStatus(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.GetProjectState(ctx, aorsdk.RequestOptions{PathParameters: projectPath(projectID)})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

type projectCommand func(context.Context, aorsdk.RequestOptions) (*http.Response, error)

func pauseProject(ctx context.Context, application *app, arguments parsedArguments) error {
	return executeProjectCommand(ctx, application, arguments, "pause", func(client *aorsdk.Client) projectCommand { return client.PauseProject })
}

func resumeProject(ctx context.Context, application *app, arguments parsedArguments) error {
	return executeProjectCommand(ctx, application, arguments, "resume", func(client *aorsdk.Client) projectCommand { return client.ResumeProject })
}

func abortProject(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := confirmAbort(application, projectID); err != nil {
		return err
	}
	return executeProjectCommand(ctx, application, arguments, "abort", func(client *aorsdk.Client) projectCommand { return client.AbortProject })
}

func executeProjectCommand(ctx context.Context, application *app, arguments parsedArguments, name string, selectCall func(*aorsdk.Client) projectCommand) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	snapshot, err := application.getProjectSnapshot(ctx, projectID)
	if err != nil {
		return err
	}
	if snapshot.Version < 1 {
		return runtimeError("INVALID_SERVER_RESPONSE", "project version must be at least 1 before "+name)
	}
	key, err := idempotencyKey(arguments)
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := selectCall(client)(ctx, aorsdk.RequestOptions{
		PathParameters: projectPath(projectID), Headers: commandHeaders(key, snapshot.ETag),
		Body: map[string]any{"expectedVersion": snapshot.Version},
	})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func confirmAbort(application *app, projectID string) error {
	if application.globals.yes {
		return nil
	}
	if application.globals.tokenStdin {
		return usageError("project abort with --token-stdin also requires --yes because standard input is reserved for the token")
	}
	_, _ = io.WriteString(application.config.Stderr, "Type the project ID to confirm abort ("+projectID+"): ")
	reader := bufio.NewReader(io.LimitReader(application.config.Stdin, 512))
	answer, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return runtimeError("CONFIRMATION_FAILED", "could not read abort confirmation")
	}
	if strings.TrimSpace(answer) != projectID {
		return runtimeError("ACTION_CANCELLED", "project abort was not confirmed")
	}
	return nil
}

func sendGoal(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	path, err := requireValue(arguments, "file")
	if err != nil {
		return err
	}
	contents, err := readBoundedFile(path)
	if err != nil {
		return err
	}
	if len(contents) == 0 || !utf8.Valid(contents) {
		return usageError("goal request file must contain valid UTF-8 text")
	}
	snapshot, err := application.getProjectSnapshot(ctx, projectID)
	if err != nil {
		return err
	}
	key, err := idempotencyKey(arguments)
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.SendGoalMessage(ctx, aorsdk.RequestOptions{
		PathParameters: projectPath(projectID), Headers: commandHeaders(key, snapshot.ETag),
		Body: map[string]any{"expectedVersion": snapshot.Version, "message": string(contents)},
	})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func diffGoal(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	from, err := requirePositiveInteger(arguments, "from")
	if err != nil {
		return err
	}
	to, err := requirePositiveInteger(arguments, "to")
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	fromResponse, err := client.GetGoalSpec(ctx, aorsdk.RequestOptions{PathParameters: versionPath(projectID, from)})
	if err != nil {
		return requestFailure(err)
	}
	fromBody, err := readResponse(fromResponse)
	if err != nil {
		return err
	}
	toResponse, err := client.GetGoalSpec(ctx, aorsdk.RequestOptions{PathParameters: versionPath(projectID, to)})
	if err != nil {
		return requestFailure(err)
	}
	toBody, err := readResponse(toResponse)
	if err != nil {
		return err
	}
	changes, err := compareJSON(fromBody, toBody)
	if err != nil {
		return err
	}
	return writeValue(application.config.Stdout, map[string]any{
		"projectId": projectID, "fromVersion": from, "toVersion": to, "changes": changes,
	}, application.globals.json)
}

func approveGoal(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	goalVersion, err := requirePositiveInteger(arguments, "version")
	if err != nil {
		return err
	}
	digest, err := normalizeSHA256(arguments.value("sha256"))
	if err != nil {
		return err
	}
	snapshot, err := application.getProjectSnapshot(ctx, projectID)
	if err != nil {
		return err
	}
	key, err := idempotencyKey(arguments)
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.ApproveGoalSpec(ctx, aorsdk.RequestOptions{
		PathParameters: versionPath(projectID, goalVersion), Headers: commandHeaders(key, snapshot.ETag),
		Body: map[string]any{"expectedVersion": snapshot.Version, "sha256": digest},
	})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func normalizeSHA256(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || len(value) != 64 {
		return "", usageError("--sha256 must be a 64-character hexadecimal SHA-256 digest")
	}
	return "sha256:" + value, nil
}

func listTasks(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	query := make(url.Values)
	if cursor := arguments.value("cursor"); cursor != "" {
		if len(cursor) > 512 || strings.ContainsAny(cursor, "\r\n\x00") {
			return usageError("--cursor is invalid")
		}
		query.Set("cursor", cursor)
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.ListTasks(ctx, aorsdk.RequestOptions{PathParameters: projectPath(projectID), Query: query})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func showTask(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID, taskID := arguments.positionals[0], arguments.positionals[1]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	if err := ensureIdentifier(taskID, "task ID"); err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.GetTask(ctx, aorsdk.RequestOptions{PathParameters: taskPath(projectID, taskID)})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func decideTask(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID, taskID := arguments.positionals[0], arguments.positionals[1]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	if err := ensureIdentifier(taskID, "task ID"); err != nil {
		return err
	}
	decision, err := normalizeDecision(arguments.value("decision"))
	if err != nil {
		return err
	}
	if decision == "ABORT_PROJECT" || decision == "ABORT_MODULE" {
		if err := confirmDecision(application, decision); err != nil {
			return err
		}
	}
	snapshot, err := application.getTaskSnapshot(ctx, projectID, taskID)
	if err != nil {
		return err
	}
	key, err := idempotencyKey(arguments)
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.DecideTask(ctx, aorsdk.RequestOptions{
		PathParameters: taskPath(projectID, taskID), Headers: commandHeaders(key, snapshot.ETag),
		Body: map[string]any{"decision": decision, "expectedVersion": snapshot.Version},
	})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func confirmDecision(application *app, decision string) error {
	if application.globals.yes {
		return nil
	}
	if application.globals.tokenStdin {
		return usageError("destructive task decisions with --token-stdin also require --yes")
	}
	_, _ = io.WriteString(application.config.Stderr, "Type "+decision+" to confirm the destructive task decision: ")
	reader := bufio.NewReader(io.LimitReader(application.config.Stdin, 512))
	answer, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return runtimeError("CONFIRMATION_FAILED", "could not read task decision confirmation")
	}
	if strings.TrimSpace(answer) != decision {
		return runtimeError("ACTION_CANCELLED", "destructive task decision was not confirmed")
	}
	return nil
}

func normalizeDecision(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	aliases := map[string]string{
		"CHANGE_GOAL": "REVISE_GOAL", "CHANGE_MODULE_SPEC": "REVISE_MODULE_SPEC",
		"HUMAN_TAKEOVER": "HAND_OFF_TO_HUMAN", "RESET_ATTEMPTS": "AUTHORIZE_NEW_ATTEMPT_SERIES",
	}
	if canonical := aliases[value]; canonical != "" {
		value = canonical
	}
	if value == "ACCEPT_RISK_AND_CONTINUE" {
		return "", formatContractGap("task decide", "ACCEPT_RISK_AND_CONTINUE is required by SPEC 16.6 but absent from TaskDecision")
	}
	if !oneOf(value, "ABORT_PROJECT", "ABORT_MODULE", "REVISE_GOAL", "REVISE_MODULE_SPEC", "HAND_OFF_TO_HUMAN", "AUTHORIZE_NEW_ATTEMPT_SERIES") {
		return "", usageError("--decision is not a supported task decision")
	}
	return value, nil
}

func showAudit(ctx context.Context, application *app, arguments parsedArguments) error {
	auditID := arguments.positionals[0]
	projectID, taskID := arguments.value("project"), arguments.value("task")
	if parsed, err := url.Parse(auditID); err == nil && parsed.Scheme == "audit" {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if projectID == "" {
			projectID = parsed.Host
		}
		if taskID == "" && len(parts) >= 1 {
			taskID = parts[0]
		}
	}
	if projectID == "" || taskID == "" {
		return formatContractGap("audit show", "the API has no audit-by-ID route; provide --project and --task so the CLI can search the task audit page")
	}
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	if err := ensureIdentifier(taskID, "task ID"); err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.ListTaskAudits(ctx, aorsdk.RequestOptions{PathParameters: taskPath(projectID, taskID)})
	if err != nil {
		return requestFailure(err)
	}
	body, err := readResponse(response)
	if err != nil {
		return err
	}
	items, err := parsePage(body)
	if err != nil {
		return err
	}
	for _, item := range items {
		if jsonItemMatches(item, auditID, "id", "auditId", "runId", "uri") {
			var value any
			if json.Unmarshal(item, &value) != nil {
				return runtimeError("INVALID_SERVER_RESPONSE", "the matching audit is invalid JSON")
			}
			return writeValue(application.config.Stdout, value, application.globals.json)
		}
	}
	return runtimeError("NOT_FOUND", "audit was not present in the task audit page")
}

func downloadArtifact(ctx context.Context, application *app, arguments parsedArguments) error {
	artifactURI := arguments.positionals[0]
	parsed, err := validateURI(artifactURI)
	if err != nil {
		return err
	}
	if parsed.Scheme != "artifact" || parsed.Host != "sha256" {
		return usageError("artifact URI must use artifact://sha256/<digest>")
	}
	digest := strings.TrimPrefix(parsed.Path, "/")
	if _, err := normalizeSHA256(digest); err != nil {
		return usageError("artifact URI must contain a valid SHA-256 digest")
	}
	projectID := arguments.value("project")
	if projectID == "" {
		return formatContractGap("artifact download", "content-addressed artifact URIs do not contain a project ID, while the API requires one; pass --project")
	}
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	artifactID := ""
	cursor := ""
	seenCursors := make(map[string]struct{})
	for pageNumber := 0; pageNumber < 100 && artifactID == ""; pageNumber++ {
		query := make(url.Values)
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		listResponse, requestErr := client.ListArtifacts(ctx, aorsdk.RequestOptions{PathParameters: projectPath(projectID), Query: query})
		if requestErr != nil {
			return requestFailure(requestErr)
		}
		body, responseErr := readResponse(listResponse)
		if responseErr != nil {
			return responseErr
		}
		items, nextCursor, pageErr := parsePageWithCursor(body)
		if pageErr != nil {
			return pageErr
		}
		for _, item := range items {
			if jsonItemMatches(item, artifactURI, "uri") {
				artifactID = jsonStringField(item, "id", "artifactId")
				break
			}
		}
		if artifactID != "" || nextCursor == "" {
			break
		}
		if _, duplicate := seenCursors[nextCursor]; duplicate {
			return runtimeError("INVALID_SERVER_RESPONSE", "the server repeated an artifact page cursor")
		}
		seenCursors[nextCursor] = struct{}{}
		cursor = nextCursor
		if pageNumber == 99 {
			return runtimeError("RESULT_SET_TOO_LARGE", "artifact lookup exceeds 100 pages")
		}
	}
	if artifactID == "" {
		return runtimeError("NOT_FOUND", "artifact was not present in the project artifact page")
	}
	response, err := client.GetArtifact(ctx, aorsdk.RequestOptions{PathParameters: map[string]string{"projectId": projectID, "artifactId": artifactID}})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitArtifactContent(response)
}

func knowledgeReferences(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	query, err := requireValue(arguments, "query")
	if err != nil {
		return err
	}
	if len(query) > 16<<10 || !utf8.ValidString(query) || strings.ContainsRune(query, '\x00') {
		return usageError("--query is invalid or exceeds 16 KiB")
	}
	snapshot, err := application.getProjectSnapshot(ctx, projectID)
	if err != nil {
		return err
	}
	key, err := idempotencyKey(arguments)
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.SearchKnowledge(ctx, aorsdk.RequestOptions{
		PathParameters: projectPath(projectID), Headers: commandHeaders(key, snapshot.ETag),
		Body: map[string]any{"expectedVersion": snapshot.Version, "query": query},
	})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func showBudget(ctx context.Context, application *app, arguments parsedArguments) error {
	projectID := arguments.positionals[0]
	if err := ensureIdentifier(projectID, "project ID"); err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := client.GetBudgets(ctx, aorsdk.RequestOptions{PathParameters: projectPath(projectID)})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

type adminCommand func(context.Context, aorsdk.RequestOptions) (*http.Response, error)

func runDoctor(ctx context.Context, application *app, arguments parsedArguments) error {
	return executeAdminCommand(ctx, application, arguments, func(client *aorsdk.Client) adminCommand { return client.RunDoctor })
}

func testPolicies(ctx context.Context, application *app, arguments parsedArguments) error {
	return executeAdminCommand(ctx, application, arguments, func(client *aorsdk.Client) adminCommand { return client.TestPolicies })
}

func probeSandboxes(ctx context.Context, application *app, arguments parsedArguments) error {
	return executeAdminCommand(ctx, application, arguments, func(client *aorsdk.Client) adminCommand { return client.ProbeSandboxes })
}

func executeAdminCommand(ctx context.Context, application *app, arguments parsedArguments, selectCall func(*aorsdk.Client) adminCommand) error {
	body, err := readJSONObject(arguments.value("file"))
	if err != nil {
		return err
	}
	key, err := idempotencyKey(arguments)
	if err != nil {
		return err
	}
	client, err := application.api()
	if err != nil {
		return err
	}
	response, err := selectCall(client)(ctx, aorsdk.RequestOptions{Headers: commandHeaders(key, ""), Body: body})
	if err != nil {
		return requestFailure(err)
	}
	return application.emitResponse(response)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func jsonItemMatches(raw json.RawMessage, expected string, fields ...string) bool {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	for _, field := range fields {
		var candidate string
		if json.Unmarshal(value[field], &candidate) == nil && candidate == expected {
			return true
		}
	}
	return false
}

func jsonStringField(raw json.RawMessage, fields ...string) string {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	for _, field := range fields {
		var candidate string
		if json.Unmarshal(value[field], &candidate) == nil && candidate != "" {
			return candidate
		}
	}
	return ""
}
