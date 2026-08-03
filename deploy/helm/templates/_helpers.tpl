{{- define "aor.name" -}}
{{- default .Chart.Name .Values.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aor.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "aor.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aor.serviceAccountName" -}}
{{- include "aor.fullname" . -}}
{{- end -}}
