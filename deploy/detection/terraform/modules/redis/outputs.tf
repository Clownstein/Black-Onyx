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
