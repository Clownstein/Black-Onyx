variable "host" {
  type        = string
  description = "Postgres hostname reachable from detection workloads (matches Helm service DNS style, e.g. postgres)."
}

variable "port" {
  type        = number
  description = "Postgres port."
  default     = 5432
}

variable "username" {
  type        = string
  description = "Application DB user (inject password via secret, not this module)."
  default     = "anomaly"
}

variable "database_names" {
  type        = list(string)
  description = "Logical databases expected by detection services (see deploy/detection/init/01-databases.sql)."
  default = [
    "incident_api",
    "asset_registry",
    "threat_intel",
    "integration_hub",
    "notification_service",
    "response_orchestrator",
    "training_orchestrator",
    "smoke",
  ]
}

variable "ssl_mode" {
  type        = string
  description = "libpq sslmode hint for URL builders."
  default     = "prefer"
}
