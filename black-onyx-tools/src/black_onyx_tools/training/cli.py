"""CLI for validating, exporting, and optionally training MCP tool-use datasets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from black_onyx_tools.training.tool_use_dataset import (
    DEFAULT_DATASET_DIR,
    load_examples,
    load_tools,
    split_examples,
    validate_examples,
)
from black_onyx_tools.training.tool_use_export import (
    export_gemma_declarations,
    export_gemma_native,
    export_hf_sft,
    export_openai_finetune,
)
from black_onyx_tools.training.tool_use_train import train_tool_use_lora


def _default_out(name: str) -> Path:
    return DEFAULT_DATASET_DIR / "build" / name


def cmd_validate(args: argparse.Namespace) -> int:
    fmt = "gemma" if args.gemma else "openai"
    examples = load_examples(args.examples, fmt=fmt)
    tools = load_tools(args.tools)
    issues = validate_examples(
        examples,
        tools,
        require_full_coverage=not args.gemma,
    )
    if issues:
        for issue in issues:
            print(f"[{issue.example_id}] {issue.message}")
        return 1
    print(f"OK — {len(examples)} examples, {len(tools)} tools")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    examples = load_examples(args.examples, fmt="openai")
    train, val = split_examples(examples, val_ratio=args.val_ratio, seed=args.seed)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.format in {"openai", "all"}:
        n_train = export_openai_finetune(train, out_dir / "train_openai.jsonl")
        n_val = export_openai_finetune(val, out_dir / "val_openai.jsonl")
        print(f"OpenAI: train={n_train} val={n_val}")

    if args.format in {"hf", "all"}:
        n_train = export_hf_sft(train, out_dir / "train_hf.jsonl", template="openai")
        n_val = export_hf_sft(val, out_dir / "val_hf.jsonl", template="openai")
        print(f"HF: train={n_train} val={n_val}")

    if args.format in {"gemma", "all"}:
        gemma = load_examples(args.gemma_examples, fmt="gemma")
        g_train, g_val = split_examples(gemma, val_ratio=args.val_ratio, seed=args.seed)
        n_train = export_gemma_native(g_train, out_dir / "train_gemma.jsonl")
        n_val = export_gemma_native(g_val, out_dir / "val_gemma.jsonl")
        print(f"Gemma: train={n_train} val={n_val}")

    if args.format in {"gemma-declarations", "all"}:
        tools = load_tools(args.tools)
        n_decl = export_gemma_declarations(tools, out_dir / "gemma_tool_declarations.txt")
        print(f"Gemma declarations: {n_decl}")

    manifest = {
        "train_rows": len(train),
        "val_rows": len(val),
        "format": args.format,
        "out_dir": str(out_dir),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    train_file = Path(args.train_file)
    if not train_file.is_file():
        export_dir = Path(args.out_dir)
        examples = load_examples(args.examples, fmt="openai")
        train, val = split_examples(examples, val_ratio=args.val_ratio, seed=args.seed)
        export_dir.mkdir(parents=True, exist_ok=True)
        export_hf_sft(train, train_file := export_dir / "train_hf.jsonl")
        export_hf_sft(val, export_dir / "val_hf.jsonl")

    result = train_tool_use_lora(
        train_file=train_file,
        val_file=Path(args.val_file) if args.val_file else None,
        output_dir=Path(args.output_dir),
        base_model=args.base_model,
        num_train_epochs=args.epochs,
        max_steps=args.max_steps,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Black Onyx MCP tool-use fine-tune helper")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="Validate examples against tools.json")
    validate.add_argument("--examples", type=Path, default=DEFAULT_DATASET_DIR / "examples.jsonl")
    validate.add_argument("--tools", type=Path, default=DEFAULT_DATASET_DIR / "tools.json")
    validate.add_argument("--gemma", action="store_true", help="Validate examples_gemma.jsonl")
    validate.set_defaults(func=cmd_validate)

    export = sub.add_parser("export", help="Export train/val JSONL for external or in-repo trainers")
    export.add_argument("--examples", type=Path, default=DEFAULT_DATASET_DIR / "examples.jsonl")
    export.add_argument("--gemma-examples", type=Path, default=DEFAULT_DATASET_DIR / "examples_gemma.jsonl")
    export.add_argument("--tools", type=Path, default=DEFAULT_DATASET_DIR / "tools.json")
    export.add_argument("--out-dir", type=Path, default=_default_out("export"))
    export.add_argument(
        "--format",
        choices=["openai", "hf", "gemma", "gemma-declarations", "all"],
        default="all",
    )
    export.add_argument("--val-ratio", type=float, default=0.1)
    export.add_argument("--seed", type=int, default=42)
    export.set_defaults(func=cmd_export)

    train = sub.add_parser("train", help="LoRA SFT via TRL (requires --extra train)")
    train.add_argument("--examples", type=Path, default=DEFAULT_DATASET_DIR / "examples.jsonl")
    train.add_argument("--train-file", type=Path, default=_default_out("export") / "train_hf.jsonl")
    train.add_argument("--val-file", type=Path, default="")
    train.add_argument("--out-dir", type=Path, default=_default_out("export"))
    train.add_argument("--output-dir", type=Path, default=_default_out("adapter"))
    train.add_argument("--base-model", default="google/gemma-2-2b-it", help="HF model id (gated models need HF_TOKEN)")
    train.add_argument("--epochs", type=float, default=1.0)
    train.add_argument("--max-steps", type=int, default=-1)
    train.add_argument("--val-ratio", type=float, default=0.1)
    train.add_argument("--seed", type=int, default=42)
    train.add_argument("--dry-run", action="store_true", help="Load data + preview chat template only")
    train.set_defaults(func=cmd_train)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    code = args.func(args)
    sys.exit(code)


if __name__ == "__main__":
    main()
