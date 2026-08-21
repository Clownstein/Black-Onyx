/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DETECTION_USE_MOCK?: string
  readonly VITE_GRAFANA_URL?: string
  readonly VITE_INTEGRATION_HUB_ENABLED?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
