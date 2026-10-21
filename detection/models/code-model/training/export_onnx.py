#!/usr/bin/env python3
"""Export code-model torch encoder artifacts to ONNX (and optional int8 note).

Usage:
    uv run python training/export_onnx.py --artifacts-dir ../artifacts
    uv run python training/export_onnx.py --artifacts-dir ../artifacts --encoder hf
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def export_distil(artifacts_dir: Path) -> Path:
    import torch

    from code_model.encoder import DistilCodeEncoder, MAX_LEN

    pt_path = artifacts_dir / "distil_encoder.pt"
    if not pt_path.is_file():
        raise SystemExit(f"Missing {pt_path}")
    enc = DistilCodeEncoder()
    enc.load_state_dict(torch.load(pt_path, map_location="cpu", weights_only=True))
    enc.eval()
    dummy = torch.zeros(1, MAX_LEN, dtype=torch.long)
    onnx_path = artifacts_dir / "model.onnx"
    torch.onnx.export(
        enc,
        dummy,
        str(onnx_path),
        input_names=["input_ids"],
        output_names=["score"],
        dynamic_axes={"input_ids": {0: "batch"}, "score": {0: "batch"}},
        opset_version=17,
        dynamo=False,
    )
    return onnx_path


def export_hf(artifacts_dir: Path) -> Path:
    import torch

    from code_model.hf_encoder import HFCodeRiskEncoder, MAX_LEN

    cfg_path = artifacts_dir / "config.json"
    model_name = "microsoft/codebert-base"
    if cfg_path.is_file():
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        model_name = str(cfg.get("hf_model_name", model_name))
    pt_path = artifacts_dir / "hf_encoder.pt"
    if not pt_path.is_file():
        raise SystemExit(f"Missing {pt_path}")
    enc = HFCodeRiskEncoder(model_name=model_name, max_len=MAX_LEN)
    enc.load_state_dict(torch.load(pt_path, map_location="cpu", weights_only=True))
    enc.eval()
    dummy_ids = torch.zeros(1, MAX_LEN, dtype=torch.long)
    dummy_mask = torch.ones(1, MAX_LEN, dtype=torch.long)
    onnx_path = artifacts_dir / "model.onnx"
    torch.onnx.export(
        enc,
        (dummy_ids, dummy_mask),
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["score"],
        dynamic_axes={
            "input_ids": {0: "batch"},
            "attention_mask": {0: "batch"},
            "score": {0: "batch"},
        },
        opset_version=17,
        dynamo=False,
    )
    return onnx_path


def quantize_int8(onnx_path: Path) -> Path:
    """Dynamic int8 quantization for CPU inference (optional size/latency win)."""
    try:
        from onnxruntime.quantization import QuantType, quantize_dynamic
    except ImportError as exc:
        raise SystemExit("onnxruntime quantization requires onnxruntime>=1.16") from exc

    out_path = onnx_path.with_name("model.int8.onnx")
    quantize_dynamic(
        model_input=str(onnx_path),
        model_output=str(out_path),
        weight_type=QuantType.QInt8,
    )
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Export code-model encoder to ONNX")
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument(
        "--encoder",
        choices=("distil", "hf"),
        default="distil",
        help="Which checkpoint to export",
    )
    parser.add_argument(
        "--int8",
        action="store_true",
        help="Also emit model.int8.onnx via onnxruntime dynamic quantization",
    )
    args = parser.parse_args()
    if args.encoder == "hf":
        out = export_hf(args.artifacts_dir)
    else:
        out = export_distil(args.artifacts_dir)
    print(f"Wrote {out}")
    if args.int8:
        int8_path = quantize_int8(out)
        print(f"Wrote {int8_path}")


if __name__ == "__main__":
    main()
