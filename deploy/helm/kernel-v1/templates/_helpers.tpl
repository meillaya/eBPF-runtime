{{/*
SPDX-License-Identifier: Apache-2.0 OR MIT

Template helpers for the kernel-v1 Helm chart.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "kernel-v1.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars because some Kubernetes name fields are limited to
this (by the DNS naming spec). If the release name contains the chart name
it will be used as a full name.
*/}}
{{- define "kernel-v1.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kernel-v1.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "kernel-v1.labels" -}}
helm.sh/chart: {{ include "kernel-v1.chart" . }}
{{ include "kernel-v1.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: kernel-v1
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "kernel-v1.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kernel-v1.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Agent component labels.
*/}}
{{- define "kernel-v1.agent.labels" -}}
{{ include "kernel-v1.labels" . }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
Agent selector labels.
*/}}
{{- define "kernel-v1.agent.selectorLabels" -}}
{{ include "kernel-v1.selectorLabels" . }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
Control-plane component labels.
*/}}
{{- define "kernel-v1.controlPlane.labels" -}}
{{ include "kernel-v1.labels" . }}
app.kubernetes.io/component: control-plane
{{- end }}

{{/*
Control-plane selector labels.
*/}}
{{- define "kernel-v1.controlPlane.selectorLabels" -}}
{{ include "kernel-v1.selectorLabels" . }}
app.kubernetes.io/component: control-plane
{{- end }}

{{/*
Migration component labels.
*/}}
{{- define "kernel-v1.migrations.labels" -}}
{{ include "kernel-v1.labels" . }}
app.kubernetes.io/component: migrations
{{- end }}

{{/*
Render an image reference. Digest takes precedence over tag.
Usage: {{ include "kernel-v1.image" (dict "image" .Values.agent.image) }}
*/}}
{{- define "kernel-v1.image" -}}
{{- if .image.digest }}
{{- printf "%s@%s" .image.repository .image.digest }}
{{- else }}
{{- printf "%s:%s" .image.repository .image.tag }}
{{- end }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "kernel-v1.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kernel-v1.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL connection environment variables.
Reads credentials from the referenced Secret (never inline).
*/}}
{{- define "kernel-v1.postgresql.env" -}}
- name: DATABASE_HOST
  value: {{ .Values.external.postgresql.host | quote }}
- name: DATABASE_PORT
  value: {{ .Values.external.postgresql.port | quote }}
- name: DATABASE_NAME
  value: {{ .Values.external.postgresql.database | quote }}
{{- if .Values.secrets.postgresql.name }}
- name: DATABASE_USER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.postgresql.name }}
      key: {{ .Values.secrets.postgresql.usernameKey }}
- name: DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.postgresql.name }}
      key: {{ .Values.secrets.postgresql.passwordKey }}
{{- end }}
{{- end }}

{{/*
Kafka connection environment variables.
*/}}
{{- define "kernel-v1.kafka.env" -}}
- name: KAFKA_BROKERS
  value: {{ .Values.external.kafka.brokers | quote }}
{{- if .Values.secrets.kafka.name }}
- name: KAFKA_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.kafka.name }}
      key: {{ .Values.secrets.kafka.usernameKey }}
- name: KAFKA_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.kafka.name }}
      key: {{ .Values.secrets.kafka.passwordKey }}
{{- end }}
{{- end }}

{{/*
ClickHouse connection environment variables.
*/}}
{{- define "kernel-v1.clickhouse.env" -}}
- name: CLICKHOUSE_HOST
  value: {{ .Values.external.clickhouse.host | quote }}
- name: CLICKHOUSE_PORT
  value: {{ .Values.external.clickhouse.port | quote }}
{{- if .Values.secrets.clickhouse.name }}
- name: CLICKHOUSE_USER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.clickhouse.name }}
      key: {{ .Values.secrets.clickhouse.usernameKey }}
- name: CLICKHOUSE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.clickhouse.name }}
      key: {{ .Values.secrets.clickhouse.passwordKey }}
{{- end }}
{{- end }}

{{/*
SPIRE connection environment variables.
*/}}
{{- define "kernel-v1.spire.env" -}}
- name: SPIRE_SERVER_ADDRESS
  value: {{ .Values.external.spire.serverAddress | quote }}
{{- end }}

{{/*
OIDC connection environment variables.
*/}}
{{- define "kernel-v1.oidc.env" -}}
- name: OIDC_ISSUER
  value: {{ .Values.external.oidc.issuer | quote }}
- name: OIDC_CLIENT_ID
  value: {{ .Values.external.oidc.clientId | quote }}
{{- if .Values.secrets.oidc.name }}
- name: OIDC_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.oidc.name }}
      key: {{ .Values.secrets.oidc.clientSecretKey }}
{{- end }}
{{- end }}
