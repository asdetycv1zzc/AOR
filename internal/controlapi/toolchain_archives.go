package controlapi

import (
	"bufio"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const (
	maximumToolchainArchiveFormBytes = artifact.MaxUserUploadBytes + 1<<20
	toolchainArchiveUploadTimeout    = 4 * time.Hour
)

type toolchainArchiveResource struct {
	ID           string `json:"id"`
	ArtifactRef  string `json:"artifactRef"`
	SourceSHA256 string `json:"sourceSha256"`
	SizeBytes    int64  `json:"sizeBytes"`
	ToolName     string `json:"toolName"`
	ToolVersion  string `json:"toolVersion"`
	Architecture string `json:"architecture"`
	Linked       bool   `json:"linked"`
}

type toolchainArchiveFields struct {
	ToolName     string
	ToolVersion  string
	Architecture string
	File         *multipart.Part
	SizeBytes    int64
}

func (handler *Handler) uploadToolchainArchive(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	deadline := time.Now().Add(toolchainArchiveUploadTimeout)
	controller := http.NewResponseController(response)
	if err := controller.SetReadDeadline(deadline); err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "toolchain archive read deadline"}))
		return
	}
	if err := controller.SetWriteDeadline(deadline); err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "toolchain archive write deadline"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	project, found, err := handler.orchestrator.Project(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if project.State != contracts.ProjectGoalNegotiating && project.State != contracts.ProjectGoalSuspended {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "toolchain archive upload"}))
		return
	}
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, authz.ActionProjectCommand, "project", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.userUploads == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "artifact upload"}))
		return
	}

	fields, err := readToolchainArchiveFields(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	defer fields.File.Close()
	if err := validateToolchainArchiveFields(fields); err != nil {
		writeError(response, request, err)
		return
	}
	buffered := bufio.NewReaderSize(fields.File, 2)
	magic, err := buffered.Peek(2)
	if err != nil || magic[0] != 0x1f || magic[1] != 0x8b {
		writeError(response, request, invalidToolchainArchive("gzip payload"))
		return
	}
	record, err := handler.userUploads.PublishUserUpload(request.Context(), artifact.UserUpload{
		TenantID: principal.TenantID, ProjectID: projectID, IdempotencyKey: idempotencyKey,
		CreatedByPrincipal: principal.ID, ContentType: "application/gzip", Body: buffered, SizeBytes: fields.SizeBytes,
		Metadata: map[string]any{
			"kind": "crosstool-ng-archive", "toolName": fields.ToolName,
			"toolVersion": fields.ToolVersion, "architecture": fields.Architecture,
		},
	})
	if err != nil {
		writeError(response, request, normalizeArtifactError(err))
		return
	}
	writeJSON(response, http.StatusCreated, toolchainArchiveResource{
		ID: record.ID, ArtifactRef: record.URI, SourceSHA256: record.SHA256,
		SizeBytes: record.SizeBytes, ToolName: fields.ToolName,
		ToolVersion: fields.ToolVersion, Architecture: fields.Architecture, Linked: false,
	})
}

func readToolchainArchiveFields(request *http.Request) (toolchainArchiveFields, error) {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || parameters["boundary"] == "" {
		return toolchainArchiveFields{}, invalidToolchainArchive("content type")
	}
	if request.ContentLength > maximumToolchainArchiveFormBytes {
		return toolchainArchiveFields{}, aorerrors.New(aorerrors.CodeToolOutputTooLarge, "", map[string]any{"scope": "toolchain archive"})
	}
	reader := multipart.NewReader(io.LimitReader(request.Body, maximumToolchainArchiveFormBytes+1), parameters["boundary"])
	fields := toolchainArchiveFields{SizeBytes: -1}
	seen := make(map[string]struct{}, 4)
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return toolchainArchiveFields{}, invalidToolchainArchive("multipart body")
		}
		name := part.FormName()
		if _, duplicate := seen[name]; duplicate || name == "" {
			part.Close()
			return toolchainArchiveFields{}, invalidToolchainArchive("multipart field")
		}
		seen[name] = struct{}{}
		switch name {
		case "toolName", "toolVersion", "architecture":
			value, readErr := readSmallMultipartField(part)
			part.Close()
			if readErr != nil {
				return toolchainArchiveFields{}, invalidToolchainArchive(name)
			}
			switch name {
			case "toolName":
				fields.ToolName = value
			case "toolVersion":
				fields.ToolVersion = value
			case "architecture":
				fields.Architecture = value
			}
		case "file":
			partMediaType, _, mediaErr := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if !strings.HasSuffix(strings.ToLower(part.FileName()), ".tar.gz") || fields.File != nil || mediaErr != nil ||
				partMediaType != "application/gzip" && partMediaType != "application/x-gzip" {
				part.Close()
				return toolchainArchiveFields{}, invalidToolchainArchive("file")
			}
			if fields.ToolName == "" || fields.ToolVersion == "" || fields.Architecture == "" {
				part.Close()
				return toolchainArchiveFields{}, invalidToolchainArchive("field order")
			}
			fields.File = part
			return fields, nil
		default:
			part.Close()
			return toolchainArchiveFields{}, invalidToolchainArchive("multipart field")
		}
	}
	return fields, nil
}

func readSmallMultipartField(part *multipart.Part) (string, error) {
	value, err := io.ReadAll(io.LimitReader(part, 257))
	if err != nil || len(value) == 0 || len(value) > 256 {
		return "", artifact.ErrInvalidRequest
	}
	return string(value), nil
}

func validateToolchainArchiveFields(fields toolchainArchiveFields) error {
	if fields.File == nil {
		return invalidToolchainArchive("file")
	}
	language := "C"
	if strings.Contains(strings.ToLower(fields.ToolName), "++") {
		language = "C++"
	}
	selection := contracts.GoalToolchain{
		Languages: []contracts.LanguageRequirement{{Name: language, Version: "C23"}},
		Tools: []contracts.VersionedTool{{
			Kind: contracts.ToolchainCompiler, Name: fields.ToolName, Version: fields.ToolVersion,
			Platform: contracts.PlatformLinux, Architecture: fields.Architecture,
			Source:  contracts.ToolchainInstallRequired,
			Install: &contracts.ToolchainInstall{Method: contracts.ToolchainInstallManual},
		}},
	}
	if selection.Validate() != nil {
		return invalidToolchainArchive("toolName")
	}
	return nil
}

func invalidToolchainArchive(scope string) error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "toolchain archive " + scope})
}
