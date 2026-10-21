-- Platform auth/TIP and security-gateway databases
CREATE DATABASE black_onyx;
CREATE DATABASE security_gateway;

GRANT ALL PRIVILEGES ON DATABASE black_onyx TO anomaly;
GRANT ALL PRIVILEGES ON DATABASE security_gateway TO anomaly;
