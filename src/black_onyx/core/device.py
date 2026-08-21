"""Device detection — PyTorch only, no TensorFlow."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_device: str | None = None


def get_device() -> str:
    """Detect and return the best available torch device.

    Returns 'cuda' if CUDA is available, 'mps' if Apple Silicon MPS is available,
    otherwise 'cpu'. The result is cached after the first call.

    Returns:
        Device string: 'cuda', 'mps', or 'cpu'.
    """
    global _device
    if _device is not None:
        return _device

    try:
        import torch

        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            gpu_count = torch.cuda.device_count()
            logger.info(f"CUDA available: {gpu_name} ({gpu_count} device(s))")
            _device = "cuda"
            return _device

        # Apple Silicon MPS
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            logger.info("Apple MPS available")
            _device = "mps"
            return _device

    except ImportError:
        logger.warning("PyTorch not installed; defaulting to CPU")

    logger.info("Using CPU device")
    _device = "cpu"
    return _device


def get_device_info() -> dict:
    """Get detailed device information for the system info API.

    Returns:
        Dict with device, gpu_name, cuda_version, gpu_memory info.
    """
    info: dict = {"device": get_device()}

    try:
        import torch

        info["torch_version"] = torch.__version__

        if torch.cuda.is_available():
            info["gpu_name"] = torch.cuda.get_device_name(0)
            info["gpu_count"] = torch.cuda.device_count()
            info["cuda_version"] = torch.version.cuda or "N/A"
            props = torch.cuda.get_device_properties(0)
            info["gpu_total_memory_gb"] = round(props.total_memory / 1e9, 2)
            # Current memory usage if available
            try:
                allocated = torch.cuda.memory_allocated(0)
                info["gpu_allocated_memory_mb"] = round(allocated / 1e6, 1)
            except Exception as exc:
                logger.debug("GPU allocation metrics unavailable: %s", type(exc).__name__)
        else:
            info["gpu_name"] = None
            info["cuda_version"] = None

    except ImportError:
        info["torch_version"] = "not installed"

    return info
