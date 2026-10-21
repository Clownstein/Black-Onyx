"""Sandbox Firecracker integration optional microVM isolation.

Merged from model-tools/sandbox/firecracker.py. Provides an optional
Firecracker microVM isolation layer for high-risk tool executions. When
configured, the runner can dispatch executions to a Firecracker microVM
instead of a Docker container for stronger isolation.

This module is imported lazily and only used when SANDBOX_ISOLATION=firecracker
is configured. The Docker-based isolation (the default) is handled by the
runner service directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Firecracker binary paths (operator-configured)
FIRECRACKER_BIN = "/usr/local/bin/firecracker"
JAILER_BIN = "/usr/local/bin/jailer"

# Default microVM resources
DEFAULT_VCPU_COUNT = 1
DEFAULT_MEM_SIZE_MIB = 256
DEFAULT_TIMEOUT_SECONDS = 30


@dataclass
class MicroVMConfig:
    """Configuration for a Firecracker microVM."""
    kernel_image: Path
    rootfs: Path
    vcpu_count: int = DEFAULT_VCPU_COUNT
    mem_size_mib: int = DEFAULT_MEM_SIZE_MIB
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    network: bool = False
    extra_args: list[str] = field(default_factory=list)


@dataclass
class MicroVMResult:
    """Result of a microVM execution."""
    status: str = "success"
    output: str = ""
    returncode: int = 0
    duration_s: float = 0.0


def is_firecracker_available() -> bool:
    """Check if Firecracker is available on this system."""
    return Path(FIRECRACKER_BIN).exists() and Path(JAILER_BIN).exists()


async def execute_in_microvm(
    command: str,
    config: MicroVMConfig,
    *,
    workspace: Path,
) -> MicroVMResult:
    """Execute a command inside a Firecracker microVM.

    This is a placeholder implementation. The full implementation would:
    1. Create a jailer configuration
    2. Start the Firecracker process with the kernel and rootfs
    3. Wait for the VM to boot
    4. Execute the command via the VM's serial console or vsock
    5. Collect output and return code
    6. Tear down the VM

    Raises NotImplementedError if Firecracker is not available.
    """
    if not is_firecracker_available():
        raise NotImplementedError("Firecracker is not available on this system")

    logger.info(
        "Firecracker execution: command=%r, vcpu=%d, mem=%dMIB",
        command, config.vcpu_count, config.mem_size_mib,
    )

    # Placeholder the full implementation requires a Firecracker SDK
    # and a pre-built kernel/rootfs image.
    return MicroVMResult(
        status="error",
        output="Firecracker execution not yet implemented",
        returncode=1,
    )


def build_firecracker_config(
    *,
    kernel: str,
    rootfs: str,
    vcpu: int = DEFAULT_VCPU_COUNT,
    mem_mib: int = DEFAULT_MEM_SIZE_MIB,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    network: bool = False,
) -> MicroVMConfig:
    """Build a MicroVMConfig from string parameters."""
    return MicroVMConfig(
        kernel_image=Path(kernel),
        rootfs=Path(rootfs),
        vcpu_count=vcpu,
        mem_size_mib=mem_mib,
        timeout_seconds=timeout,
        network=network,
    )
