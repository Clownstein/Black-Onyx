variable "brokers" {
  type        = list(string)
  description = "Kafka/Redpanda bootstrap brokers as seen by in-cluster apps (Compose: redpanda:9092; host clients use localhost:19092)."
  default     = ["redpanda:9092"]
}

variable "security_protocol" {
  type        = string
  description = "Kafka security protocol hint (PLAINTEXT / SASL_SSL / …)."
  default     = "PLAINTEXT"
}

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
