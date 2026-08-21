output "brokers" {
  value       = var.brokers
  description = "Broker list for incidentApi.kafkaBrokers and processor KAFKA_BROKERS."
}

output "brokers_csv" {
  value       = join(",", var.brokers)
  description = "Comma-separated brokers for Helm string values."
}

output "security_protocol" {
  value       = var.security_protocol
  description = "Security protocol hint."
}
