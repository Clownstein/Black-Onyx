output "host" {
  value       = var.host
  description = "Postgres host for Helm / Compose consumers."
}

output "port" {
  value       = var.port
  description = "Postgres port."
}

output "username" {
  value       = var.username
  description = "DB username (password via external secret)."
}

output "database_names" {
  value       = var.database_names
  description = "Expected database names."
}

output "sqlalchemy_url_templates" {
  value = {
    for name in var.database_names :
    name => "postgresql+psycopg://${var.username}:PASSWORD@${var.host}:${var.port}/${name}?sslmode=${var.ssl_mode}"
  }
  description = "URL templates for Helm values (replace PASSWORD from a Secret)."
}
