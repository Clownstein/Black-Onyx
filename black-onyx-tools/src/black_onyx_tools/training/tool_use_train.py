"""Optional LoRA SFT for MCP tool-use datasets (requires [train] extras)."""

from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable


def _require_train_deps() -> None:
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
        import trl  # noqa: F401
        import peft  # noqa: F401
        import datasets  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "Training extras missing. Install with: "
            "uv sync --directory black-onyx-tools --extra train"
        ) from exc


def build_formatting_func(tokenizer: Any) -> Callable[[dict[str, Any]], list[str]]:
    def formatting_func(row: dict[str, Any]) -> list[str]:
        messages = row.get("messages") or []
        if not messages:
            return [""]
        if hasattr(tokenizer, "apply_chat_template"):
            text = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
            )
            return [str(text)]
        return [json.dumps(messages, ensure_ascii=False)]

    return formatting_func


def _load_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _validate_checkpoint_indexes(model_dir: Path) -> None:
    """Reject checkpoint shard paths that escape a downloaded model snapshot.

    Accelerate resolves shard names from the model index relative to the
    checkpoint directory. Validate both POSIX and Windows path syntax so a
    malicious index cannot traverse outside that directory on either host.
    """
    for index_path in model_dir.rglob("*.index.json"):
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, JSONDecodeError) as exc:
            raise ValueError(f"Invalid model checkpoint index: {index_path.name}") from exc
        weight_map = index.get("weight_map") if isinstance(index, dict) else None
        if not isinstance(weight_map, dict):
            continue
        for shard in weight_map.values():
            if not isinstance(shard, str) or not shard or "\x00" in shard:
                raise ValueError(f"Invalid checkpoint shard entry in {index_path.name}")
            posix_path = PurePosixPath(shard)
            windows_path = PureWindowsPath(shard)
            if (
                posix_path.is_absolute()
                or windows_path.is_absolute()
                or windows_path.drive
                or ".." in posix_path.parts
                or ".." in windows_path.parts
            ):
                raise ValueError(f"Checkpoint shard escapes model directory: {shard!r}")


def _resolve_model_snapshot(base_model: str) -> Path:
    """Resolve a local model or download a Hub snapshot before loading it."""
    model_path = Path(base_model).expanduser()
    if model_path.exists():
        snapshot = model_path.resolve(strict=True)
        if not snapshot.is_dir():
            raise ValueError("base_model must be a model directory or a Hugging Face repository ID")
    else:
        from huggingface_hub import snapshot_download

        snapshot = Path(snapshot_download(repo_id=base_model)).resolve(strict=True)
    _validate_checkpoint_indexes(snapshot)
    return snapshot


def train_tool_use_lora(
    *,
    train_file: Path,
    output_dir: Path,
    base_model: str,
    val_file: Path | None = None,
    num_train_epochs: float = 1.0,
    max_steps: int = -1,
    per_device_train_batch_size: int = 1,
    gradient_accumulation_steps: int = 4,
    learning_rate: float = 2e-4,
    max_seq_length: int = 4096,
    lora_r: int = 16,
    lora_alpha: int = 32,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run LoRA SFT with TRL on an exported HF JSONL file."""
    if dry_run:
        rows = _load_jsonl_rows(train_file)
        sample = rows[0] if rows else {}
        messages = sample.get("messages") or []
        preview = json.dumps(messages[:3], ensure_ascii=False)[:500]
        return {
            "status": "dry_run",
            "base_model": base_model,
            "train_rows": len(rows),
            "preview": preview,
            "note": "Dry run skips tokenizer/model download; install [train] extras for full SFT.",
        }

    _require_train_deps()

    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
    from trl import SFTTrainer

    data_files: dict[str, str] = {"train": str(train_file)}
    if val_file and val_file.is_file():
        data_files["validation"] = str(val_file)
    dataset = load_dataset("json", data_files=data_files)

    model_dir = _resolve_model_snapshot(base_model)
    tokenizer = AutoTokenizer.from_pretrained(
        str(model_dir), trust_remote_code=False, local_files_only=True
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        str(model_dir),
        trust_remote_code=False,
        local_files_only=True,
        use_safetensors=True,
        torch_dtype="auto",
        device_map="auto",
    )

    peft_config = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=num_train_epochs,
        max_steps=max_steps,
        per_device_train_batch_size=per_device_train_batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=learning_rate,
        logging_steps=10,
        save_strategy="epoch",
        report_to=[],
        bf16=False,
        fp16=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"] if "validation" in dataset else None,
        processing_class=tokenizer,
        formatting_func=build_formatting_func(tokenizer),
        peft_config=peft_config,
        max_seq_length=max_seq_length,
    )
    metrics = trainer.train().metrics
    trainer.save_model(str(output_dir / "adapter"))
    tokenizer.save_pretrained(str(output_dir / "adapter"))
    (output_dir / "train_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return {"status": "trained", "output_dir": str(output_dir), "metrics": metrics}
