-- Extra databases for Phase 0+ services
CREATE DATABASE asset_registry;
CREATE DATABASE smoke;
CREATE DATABASE incident_api;
CREATE DATABASE threat_intel;
CREATE DATABASE integration_hub;
CREATE DATABASE notification_service;
CREATE DATABASE response_orchestrator;
CREATE DATABASE training_orchestrator;

GRANT ALL PRIVILEGES ON DATABASE asset_registry TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE smoke TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE incident_api TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE threat_intel TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE integration_hub TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE notification_service TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE response_orchestrator TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE training_orchestrator TO anomaly;
