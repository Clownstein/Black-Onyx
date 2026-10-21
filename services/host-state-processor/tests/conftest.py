import os

# Unit tests never require a broker.
os.environ.setdefault("HOST_STATE_PROCESSOR_ENABLE_KAFKA", "false")
