{{- define "black-onyx-detection.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "black-onyx-detection.labels" -}}
app.kubernetes.io/name: {{ include "black-onyx-detection.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Model serving sync env for a model deployment. Replicas poll the training
orchestrator for the signed package each alias must serve.
Usage: include "black-onyx-detection.modelServingEnv" .
*/}}
{{- define "black-onyx-detection.trainingOrchestratorUrl" -}}
http://training-orchestrator.{{ .Values.namespaces.training }}.svc.cluster.local:{{ .Values.trainingOrchestrator.service.port }}
{{- end -}}

{{- define "black-onyx-detection.modelServingEnv" -}}
- name: MODEL_SERVING_ENABLED
  value: {{ .Values.modelServing.enabled | quote }}
- name: MODEL_SERVING_ROOT
  value: /var/lib/black-onyx/model-serving
- name: MODEL_SERVING_ORCHESTRATOR_URL
  value: {{ include "black-onyx-detection.trainingOrchestratorUrl" . | quote }}
- name: MODEL_SERVING_TENANT
  value: {{ required "modelServing.tenantId is required when model serving is enabled" .Values.modelServing.tenantId | quote }}
- name: MODEL_SERVING_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.name }}
      key: trainingApiKey
- name: MODEL_SERVING_SIGNING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.name }}
      key: trainingArtifactSigningKey
{{- end -}}

{{- define "black-onyx-detection.modelServingMount" -}}
- name: model-serving
  mountPath: /var/lib/black-onyx/model-serving
{{- end -}}

{{- define "black-onyx-detection.modelServingVolume" -}}
- name: model-serving
  emptyDir:
    sizeLimit: {{ .Values.modelServing.sizeLimit }}
{{- end -}}
