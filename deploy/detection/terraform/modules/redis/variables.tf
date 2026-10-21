variable "url" {
  type        = string
  description = "Redis URL for correlation-engine HA buckets (Helm correlationEngine.redisUrl)."
  default     = "redis://redis:6379/0"
  sensitive   = true
}

variable "host" {
  type        = string
  description = "Optional discrete host when not using a full URL."
  default     = "redis"
}

variable "port" {
  type        = number
  description = "Redis port."
  default     = 6379
}

variable "db" {
  type        = number
  description = "Redis logical DB index."
  default     = 0
}

output "url" {
  value       = var.url
  sensitive   = true
  description = "Redis URL for Helm correlationEngine.redisUrl (inject password via Secret)."
}

output "host" {
  value       = var.host
  description = "Redis host."
}

output "port" {
  value       = var.port
  description = "Redis port."
}

output "db" {
  value       = var.db
  description = "Redis DB index."
}
