"""Command-line interface for Black Onyx.

Commands:
    ingest    — Ingest files from a directory into Qdrant
    search    — Semantic search across collections
    chat      — Interactive RAG chat with an LLM
    collections — List and manage Qdrant collections
    info      — Show system and configuration info
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from black_onyx.config import Settings, get_settings

logger = logging.getLogger(__name__)


def _setup_logging(level: str = "INFO", structured: bool = False) -> None:
    """Configure logging for the CLI."""
    from black_onyx.core.logging_config import setup_logging
    setup_logging(level=level, structured=structured)


def _build_components(settings: Settings) -> dict[str, Any]:
    """Build all components from settings (lazy-loaded).

    Args:
        settings: Application settings.

    Returns:
        Dict of component instances.
    """
    from black_onyx.core.classifier import Classifier
    from black_onyx.core.embeddings import EmbeddingModel
    from black_onyx.core.ner import NERModel
    from black_onyx.core.qdrant_store import QdrantStore

    components: dict[str, Any] = {}

    # Embedding model
    components["embedding_model"] = EmbeddingModel(
        model_name=settings.embedding.model_name,
        device=settings.resolve_device(settings.embedding.device),
    )

    # NER model
    if settings.ingestion.enable_ner:
        components["ner_model"] = NERModel(
            model_name=settings.ner.model_name,
            labels=settings.ner.labels,
            threshold=settings.ner.threshold,
            device=settings.resolve_device(settings.ner.device),
        )

    # Classifier
    if settings.classifier.enabled:
        components["classifier"] = Classifier(
            model_name=settings.classifier.model_name,
            device=settings.resolve_device(settings.classifier.device),
            enabled=True,
        )

    # Qdrant store
    api_key = None
    if settings.qdrant.api_key:
        api_key = settings.qdrant.api_key.get_secret_value()
    components["qdrant_store"] = QdrantStore(
        host=settings.qdrant.host,
        port=settings.qdrant.port,
        api_key=api_key,
        prefer_grpc=settings.qdrant.prefer_grpc,
        timeout=settings.qdrant.timeout,
    )

    # OCR engine (optional)
    if settings.ingestion.enable_image_extraction:
        try:
            from black_onyx.extraction.ocr import OCREngine
            components["ocr_engine"] = OCREngine(
                backend=settings.ocr.backend,
                language=settings.ocr.language,
                tesseract_cmd=settings.ocr.tesseract_cmd,
            )
        except ImportError:
            logger.warning("OCR dependencies not installed; image OCR disabled")

    # CLIP model (optional)
    if settings.ingestion.enable_image_extraction:
        try:
            from black_onyx.extraction.clip import CLIPModel
            components["clip_model"] = CLIPModel(
                model_name=settings.clip.model_name,
                pretrained=settings.clip.pretrained,
                device=settings.resolve_device(settings.clip.device),
            )
        except ImportError:
            logger.warning("CLIP dependencies not installed; image embeddings disabled")

    return components


def cmd_ingest(args: argparse.Namespace, settings: Settings) -> int:
    """Run the ingest command."""
    from black_onyx.pipeline.checkpoint import CheckpointManager
    from black_onyx.pipeline.ingestor import Ingestor
    from black_onyx.pipeline.progress import ProgressTracker

    components = _build_components(settings)

    def progress_callback(data: dict) -> None:
        event = data.get("event", "")
        if event == "progress":
            print(f"  Progress: {data['processed']}/{data['total']} ({data['speed_fps']:.1f} fps)")
        elif event == "file_done":
            print(f"  ✓ {data['filepath']} ({data['chunks']} chunks)")
        elif event == "file_error":
            print(f"  ✗ {data['filepath']}: {data['error']}")
        elif event == "ingest_complete":
            print(f"\n  Complete: {data['total_chunks']} chunks, {data['total_errors']} errors, {data['duration_s']}s")

    tracker = ProgressTracker(callback=progress_callback)
    checkpoint = (
        CheckpointManager(settings.storage.state_dir) if not args.no_checkpoint else None
    )

    ingestor = Ingestor(
        embedding_model=components["embedding_model"],
        ner_model=components.get("ner_model"),
        classifier=components.get("classifier"),
        qdrant_store=components["qdrant_store"],
        ocr_engine=components.get("ocr_engine"),
        clip_model=components.get("clip_model"),
        chunk_size=settings.chunking.chunk_size,
        chunk_overlap=settings.chunking.chunk_overlap,
        sentence_aware=settings.chunking.sentence_aware,
        batch_size=settings.ingestion.batch_size,
        max_workers=settings.ingestion.max_workers,
        enable_ner=settings.ingestion.enable_ner,
        enable_classifier=settings.ingestion.enable_classifier,
        enable_code_detection=settings.ingestion.enable_code_detection,
        enable_image_extraction=settings.ingestion.enable_image_extraction,
        use_multivector=settings.image.use_multivector,
        csv_path=args.csv_path or settings.ingestion.csv_path,
    )

    directory = args.directory or settings.ingestion.directory
    collection = args.collection or settings.ingestion.collection_name

    print(f"Starting ingestion from '{directory}' into collection '{collection}'...")
    stats = ingestor.process_directory(
        directory=directory,
        collection_name=collection,
        progress_tracker=tracker,
        checkpoint_manager=checkpoint,
    )

    print(f"\nIngestion complete: {json.dumps(stats, indent=2)}")
    return 0


def cmd_search(args: argparse.Namespace, settings: Settings) -> int:
    """Run the search command."""
    components = _build_components(settings)
    store = components["qdrant_store"]
    embedding_model = components["embedding_model"]

    query_vector = embedding_model.encode_single(args.query)
    results = store.search(
        collection_name=args.collection,
        query_vector=query_vector,
        limit=args.limit,
        score_threshold=args.score_threshold,
        using="text",
    )

    if not results:
        print("No results found.")
        return 0

    print(f"Found {len(results)} results:\n")
    for i, r in enumerate(results, 1):
        payload = r.payload or {}
        source = payload.get("source_file", "unknown")
        chunk_idx = payload.get("chunk_index", 0)
        body = (payload.get("body_text") or "")[:200]
        print(f"  [{i}] Score: {r.score:.4f} | {source} (chunk {chunk_idx})")
        print(f"      {body}...")
        print()

    return 0


def cmd_chat(args: argparse.Namespace, settings: Settings) -> int:
    """Run the interactive chat command."""
    from black_onyx.llm.base import ChatMessage
    from black_onyx.llm.factory import create_provider
    from black_onyx.llm.rag import RAGEngine

    components = _build_components(settings)

    # Collect API keys from environment
    api_keys: dict[str, str] = {}
    import os
    for env_name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]:
        val = os.environ.get(env_name, "")
        if val:
            api_keys[env_name] = val

    provider = create_provider(
        provider_type=args.provider or settings.llm.provider,
        config=settings.llm,
        api_keys=api_keys,
    )

    rag = RAGEngine(
        llm_provider=provider,
        embedding_model=components["embedding_model"],
        qdrant_store=components["qdrant_store"],
        collections=settings.llm.rag.collections,
        top_k=settings.llm.rag.top_k,
        score_threshold=settings.llm.rag.score_threshold,
        chunk_context_window=settings.llm.rag.chunk_context_window,
        system_prompt=settings.llm.rag.system_prompt,
    )

    print(f"Chat with {provider.name} (RAG enabled). Type 'exit' to quit.\n")

    history: list[ChatMessage] = []

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if user_input.lower() in ("exit", "quit", "q"):
            print("Goodbye!")
            break

        if not user_input:
            continue

        response, chunks = rag.chat(user_input, history=history)

        # Update history
        history.append(ChatMessage(role="user", content=user_input))
        history.append(ChatMessage(role="assistant", content=response.text))

        print(f"\nAssistant: {response.text}")

        if chunks:
            print(f"\n  [Sources: {len(chunks)} chunks retrieved]")
            for chunk in chunks[:3]:
                source = chunk.payload.get("source_file", "unknown")
                print(f"    - {source} (score: {chunk.score:.3f})")

        print()

    return 0


def cmd_collections(args: argparse.Namespace, settings: Settings) -> int:
    """Run the collections management command."""
    components = _build_components(settings)
    store = components["qdrant_store"]

    if args.action == "list":
        collections = store.list_collections()
        if not collections:
            print("No collections found.")
            return 0
        print(f"Found {len(collections)} collections:\n")
        for col in collections:
            print(f"  {col['name']}: {col.get('points_count', 0)} points")
            if "vectors" in col:
                for vname, vinfo in col["vectors"].items():
                    print(f"    vector '{vname}': size={vinfo['size']}, distance={vinfo['distance']}")
            elif "vector_size" in col:
                print(f"    vector size: {col['vector_size']}")
        return 0

    elif args.action == "delete":
        if not args.collection_name:
            print("Error: --collection-name required for delete")
            return 1
        store.delete_collection(args.collection_name)
        print(f"Deleted collection: {args.collection_name}")
        return 0

    elif args.action == "info":
        if not args.collection_name:
            print("Error: --collection-name required for info")
            return 1
        info = store.get_collection_info(args.collection_name)
        if info:
            print(json.dumps(info, indent=2))
        else:
            print(f"Collection not found: {args.collection_name}")
        return 0

    print(f"Unknown action: {args.action}")
    return 1


def cmd_info(args: argparse.Namespace, settings: Settings) -> int:
    """Run the info command."""
    from black_onyx.core.device import get_device_info

    print("=== Black Onyx System Info ===\n")

    print("Device:")
    device_info = get_device_info()
    print(json.dumps(device_info, indent=2))

    print("\nConfiguration:")
    # Print config as dict (mask secrets)
    config_dict = settings.model_dump()
    if config_dict.get("qdrant", {}).get("api_key"):
        config_dict["qdrant"]["api_key"] = "***"
    print(json.dumps(config_dict, indent=2, default=str))

    print("\nQdrant:")
    try:
        components = _build_components(settings)
        store = components["qdrant_store"]
        collections = store.list_collections()
        print(f"  Server version: {store.get_server_version()}")
        print(f"  Collections: {len(collections)}")
        for col in collections:
            print(f"    - {col['name']}: {col.get('points_count', 0)} points")
    except Exception as e:
        print(f"  Error connecting to Qdrant: {e}")

    return 0


# ===========================
# IOC extraction command
# ===========================

def cmd_extract_iocs(args: argparse.Namespace, settings: Settings) -> int:
    """Extract IOCs from a file or text."""
    from black_onyx.extraction.ioc import extract_iocs

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        print("Error: provide --file or --text")
        return 1

    result = extract_iocs(text)
    ioc_dict = result.to_dict()

    if args.format == "json":
        print(json.dumps(ioc_dict, indent=2))
    else:
        print(f"\nExtracted {result.total_count} IOCs:\n")
        for ioc_type, values in ioc_dict.items():
            print(f"  {ioc_type} ({len(values)}):")
            for v in values:
                print(f"    - {v}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(ioc_dict, f, indent=2)
        print(f"\nSaved to {args.output}")

    return 0


# ===========================
# Enrich command
# ===========================

def cmd_enrich(args: argparse.Namespace, settings: Settings) -> int:
    """Enrich an IOC via configured providers."""
    import asyncio

    from black_onyx.enrichment.factory import create_enrichment_provider
    from black_onyx.enrichment.manager import EnrichmentManager

    api_keys: dict[str, str] = {}
    import os
    for env_name in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "OTX_API_KEY", "NVD_API_KEY"]:
        val = os.environ.get(env_name, "")
        if val:
            api_keys[env_name] = val

    providers = []
    for name in (args.providers or settings.enrichment.providers):
        try:
            providers.append(create_enrichment_provider(name, api_keys))
        except Exception as e:
            print(f"  Warning: could not create provider '{name}': {e}")

    if not providers:
        print("No enrichment providers available.")
        return 1

    mgr = EnrichmentManager(
        providers=providers,
        persist_dir=settings.storage.state_dir,
        cache_ttl_hours=settings.enrichment.cache_ttl_hours,
    )

    ioc_type = args.ioc_type
    if not ioc_type:
        ioc_type = EnrichmentManager.classify_ioc_type(args.value)

    results = asyncio.run(mgr.enrich_ioc(ioc_type, args.value))
    print(f"\nEnrichment results for {args.value} ({ioc_type}):\n")
    for r in results:
        print(f"  Provider: {r.provider}")
        print(f"    Malicious: {r.malicious}")
        print(f"    Confidence: {r.confidence}")
        if r.tags:
            print(f"    Tags: {', '.join(r.tags)}")
        if r.error:
            print(f"    Error: {r.error}")
        print()

    return 0


# ===========================
# STIX export command
# ===========================

def cmd_stix_export(args: argparse.Namespace, settings: Settings) -> int:
    """Export IOCs to STIX 2.1 bundle."""
    from black_onyx.threat.stix_exporter import STIXExporter

    iocs = []
    if args.file:
        with open(args.file, "r") as f:
            iocs = json.load(f)
    elif args.iocs:
        for ioc in args.iocs:
            parts = ioc.split(":", 1)
            if len(parts) == 2:
                iocs.append({"ioc_type": parts[0], "ioc_value": parts[1]})

    exporter = STIXExporter()
    bundle = exporter.export_bundle(iocs=iocs)

    output = json.dumps(bundle, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"STIX bundle written to {args.output}")
    else:
        print(output)

    return 0


# ===========================
# Rule generation command
# ===========================

def cmd_generate_rules(args: argparse.Namespace, settings: Settings) -> int:
    """Generate Sigma and/or YARA rules from IOCs."""
    if args.file:
        with open(args.file, "r") as f:
            iocs = json.load(f)
    else:
        print("Error: --file required with IOC JSON")
        return 1

    if args.rule_type in ("sigma", "both"):
        from black_onyx.threat.sigma_generator import SigmaRuleGenerator
        sigma_gen = SigmaRuleGenerator()
        rule = sigma_gen.generate_from_iocs(iocs, title=args.title, level=args.level)
        if args.output:
            out_file = args.output.replace(".yml", "_sigma.yml") if args.rule_type == "both" else args.output
            with open(out_file, "w") as f:
                f.write(rule)
            print(f"Sigma rule written to {out_file}")
        else:
            print("=== Sigma Rule ===")
            print(rule)

    if args.rule_type in ("yara", "both"):
        from black_onyx.threat.yara_generator import YARARuleGenerator
        yara_gen = YARARuleGenerator()
        rule = yara_gen.generate_from_iocs(iocs, rule_name=args.title or "AutoGenerated")
        if args.output:
            out_file = args.output.replace(".yml", "_yara.yar") if args.rule_type == "both" else args.output
            with open(out_file, "w") as f:
                f.write(rule)
            print(f"YARA rule written to {out_file}")
        else:
            print("=== YARA Rule ===")
            print(rule)

    return 0


# ===========================
# ATT&CK search command
# ===========================

def cmd_attack_search(args: argparse.Namespace, settings: Settings) -> int:
    """Search MITRE ATT&CK techniques."""
    from black_onyx.threat.attack_mapper import AttackMapper
    mapper = AttackMapper(data_dir=settings.threat_intel.mitre_attack_data_dir)
    results = mapper.search_techniques(args.query, limit=args.limit)
    if not results:
        print("No techniques found.")
        return 0
    print(f"\nFound {len(results)} techniques:\n")
    for tech in results:
        print(f"  {tech['technique_id']}: {tech['name']}")
        if tech.get("tactic"):
            print(f"    Tactics: {', '.join(tech['tactic'])}")
        print()
    return 0


# ===========================
# Report generate command
# ===========================

def cmd_generate_report(args: argparse.Namespace, settings: Settings) -> int:
    """Generate an intelligence report."""
    from black_onyx.threat.report_generator import ReportGenerator

    with open(args.ioc_file, "r") as f:
        iocs = json.load(f)

    llm = None
    try:
        from black_onyx.llm.factory import create_provider
        import os
        api_keys: dict[str, str] = {}
        for env_name in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"]:
            val = os.environ.get(env_name, "")
            if val:
                api_keys[env_name] = val
        llm = create_provider(settings.llm.provider, settings.llm, api_keys)
    except Exception as exc:
        logger.debug("Report LLM provider unavailable: %s", type(exc).__name__)

    gen = ReportGenerator(llm_provider=llm)
    markdown = gen.generate_markdown_report(title=args.title, iocs=iocs)

    if args.format == "html":
        content = gen.markdown_to_html(markdown)
    else:
        content = markdown

    if args.output:
        with open(args.output, "w") as f:
            f.write(content)
        print(f"Report written to {args.output}")
    else:
        print(content)

    return 0


# ===========================
# Feed poll command
# ===========================

def cmd_feed_poll(args: argparse.Namespace, settings: Settings) -> int:
    """Poll feeds for new content."""
    import asyncio
    from black_onyx.feeds.feed_manager import FeedManager

    mgr = FeedManager(
        persist_dir=settings.storage.state_dir,
        allowed_hosts=settings.feeds.allowed_hosts,
        max_response_bytes=settings.feeds.max_response_bytes,
        max_concurrent=settings.feeds.max_concurrent,
    )
    if args.feed_name:
        result = asyncio.run(mgr.poll_feed(args.feed_name))
        print(f"Feed: {result.get('feed', args.feed_name)}")
        print(f"  Items processed: {result.get('items_processed', 0)}")
        print(f"  IOCs extracted: {result.get('iocs_extracted', 0)}")
        if result.get("error"):
            print(f"  Error: {result['error']}")
    else:
        results = asyncio.run(mgr.poll_all())
        for name, result in results.items():
            print(f"Feed: {name}")
            print(f"  Items: {result.get('items_processed', 0)}, IOCs: {result.get('iocs_extracted', 0)}")
            if result.get("error"):
                print(f"  Error: {result['error']}")
    return 0


def cmd_users(args: argparse.Namespace, settings: Settings) -> int:
    """Manage Black Onyx users without exposing bootstrap over HTTP."""
    if args.user_action != "bootstrap-admin":
        raise ValueError(f"Unsupported user action: {args.user_action}")
    import getpass
    from black_onyx.auth.database import StateDatabase
    from black_onyx.auth.service import AuthService

    password = getpass.getpass("Administrator password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.")
        return 2
    service = AuthService(StateDatabase(settings.storage.state_dir), settings.security)
    principal = service.bootstrap_admin(args.email, password, args.display_name)
    print(f"Created administrator: {principal.email}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="black-onyx",
        description="Black Onyx — Consolidated data ingestion with RAG and web UI",
    )
    parser.add_argument("--config", "-c", help="Path to config.yaml", default=None)
    parser.add_argument("--log-level", help="Logging level", default=None)
    parser.add_argument("--structured-logging", action="store_true", help="Enable JSON-structured log output")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ingest
    ingest_parser = subparsers.add_parser("ingest", help="Ingest files from a directory")
    ingest_parser.add_argument("--directory", "-d", help="Directory to ingest", default=None)
    ingest_parser.add_argument("--collection", help="Qdrant collection name", default=None)
    ingest_parser.add_argument("--csv-path", help="Export results to CSV", default=None)
    ingest_parser.add_argument("--no-checkpoint", action="store_true", help="Disable checkpointing")
    ingest_parser.set_defaults(func=cmd_ingest)

    # search
    search_parser = subparsers.add_parser("search", help="Semantic search")
    search_parser.add_argument("--query", "-q", required=True, help="Search query")
    search_parser.add_argument("--collection", required=True, help="Collection to search")
    search_parser.add_argument("--limit", "-l", type=int, default=10, help="Max results")
    search_parser.add_argument("--score-threshold", type=float, default=0.0, help="Min score")
    search_parser.set_defaults(func=cmd_search)

    # chat
    chat_parser = subparsers.add_parser("chat", help="Interactive RAG chat")
    chat_parser.add_argument("--provider", help="LLM provider override", default=None)
    chat_parser.set_defaults(func=cmd_chat)

    # collections
    coll_parser = subparsers.add_parser("collections", help="Manage Qdrant collections")
    coll_parser.add_argument("action", choices=["list", "delete", "info"], help="Action")
    coll_parser.add_argument("--collection-name", help="Collection name (for delete/info)")
    coll_parser.set_defaults(func=cmd_collections)

    # info
    info_parser = subparsers.add_parser("info", help="Show system info")
    info_parser.set_defaults(func=cmd_info)

    # extract-iocs
    ioc_parser = subparsers.add_parser("extract-iocs", help="Extract IOCs from text or file")
    ioc_parser.add_argument("--file", "-f", help="File to extract IOCs from")
    ioc_parser.add_argument("--text", "-t", help="Text to extract IOCs from")
    ioc_parser.add_argument("--output", "-o", help="Output JSON file path")
    ioc_parser.add_argument("--format", choices=["text", "json"], default="text")
    ioc_parser.set_defaults(func=cmd_extract_iocs)

    # enrich
    enrich_parser = subparsers.add_parser("enrich", help="Enrich an IOC via threat intel APIs")
    enrich_parser.add_argument("value", help="IOC value to enrich")
    enrich_parser.add_argument("--ioc-type", help="IOC type (auto-detected if omitted)")
    enrich_parser.add_argument("--providers", nargs="*", help="Providers to use")
    enrich_parser.set_defaults(func=cmd_enrich)

    # stix-export
    stix_parser = subparsers.add_parser("stix-export", help="Export IOCs as STIX 2.1 bundle")
    stix_parser.add_argument("--file", "-f", help="JSON file with IOC list")
    stix_parser.add_argument("--iocs", nargs="*", help="IOCs as type:value pairs")
    stix_parser.add_argument("--output", "-o", help="Output file path")
    stix_parser.set_defaults(func=cmd_stix_export)

    # generate-rules
    rules_parser = subparsers.add_parser("generate-rules", help="Generate Sigma/YARA rules from IOCs")
    rules_parser.add_argument("--file", "-f", required=True, help="JSON file with IOCs")
    rules_parser.add_argument("--rule-type", choices=["sigma", "yara", "both"], default="both")
    rules_parser.add_argument("--title", help="Rule title")
    rules_parser.add_argument("--level", default="medium", help="Severity level")
    rules_parser.add_argument("--output", "-o", help="Output file path")
    rules_parser.set_defaults(func=cmd_generate_rules)

    # attack-search
    attack_parser = subparsers.add_parser("attack-search", help="Search MITRE ATT&CK techniques")
    attack_parser.add_argument("query", help="Search query")
    attack_parser.add_argument("--limit", "-l", type=int, default=20)
    attack_parser.set_defaults(func=cmd_attack_search)

    # generate-report
    report_parser = subparsers.add_parser("generate-report", help="Generate intelligence report")
    report_parser.add_argument("--ioc-file", "-f", required=True, help="JSON file with IOCs")
    report_parser.add_argument("--title", default="Threat Intelligence Report")
    report_parser.add_argument("--format", choices=["markdown", "html"], default="markdown")
    report_parser.add_argument("--output", "-o", help="Output file path")
    report_parser.set_defaults(func=cmd_generate_report)

    # feed-poll
    feed_parser = subparsers.add_parser("feed-poll", help="Poll feeds for new content")
    feed_parser.add_argument("--feed-name", help="Specific feed to poll (all if omitted)")
    feed_parser.set_defaults(func=cmd_feed_poll)

    users_parser = subparsers.add_parser("users", help="Manage application users")
    users_subparsers = users_parser.add_subparsers(dest="user_action", required=True)
    bootstrap_parser = users_subparsers.add_parser(
        "bootstrap-admin", help="Create the first administrator (one time only)"
    )
    bootstrap_parser.add_argument("--email", required=True)
    bootstrap_parser.add_argument("--display-name", default="Administrator")
    bootstrap_parser.set_defaults(func=cmd_users)

    return parser


def main() -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Load settings
    settings = get_settings(config_path=args.config)

    # Setup logging
    log_level = args.log_level or settings.logging.level
    structured = getattr(args, "structured_logging", False)
    _setup_logging(log_level, structured=structured)

    # Run command
    try:
        return args.func(args, settings)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
