"""Main ingestor — orchestrates extraction, chunking, embedding, NER, and Qdrant upsert."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional, cast

from qdrant_client.http.models import PointStruct

from black_onyx.extraction.chunking import chunk_text_auto
from black_onyx.extraction.code import detect_code_snippets
from black_onyx.extraction.image import (
    extract_images_from_pdf,
    is_image_file,
    process_image,
)
from black_onyx.extraction.metadata import (
    extract_metadata_from_html,
    extract_metadata_from_text,
    map_crypto_to_fields,
)
from black_onyx.extraction.text import extract_text_from_file
from black_onyx.models.data_model import DataModel
from black_onyx.models.enums import detect_file_type, FileType
from black_onyx.pipeline.checkpoint import CheckpointManager
from black_onyx.pipeline.progress import ProgressTracker

logger = logging.getLogger(__name__)


class Ingestor:
    """Main ingestion orchestration engine.

    Routes files to text or image processing pipelines, handles chunking,
    embedding, NER, classification, metadata extraction, and Qdrant upsert.
    Supports multi-vector (named vectors) collections for text + CLIP embeddings.
    """

    def __init__(
        self,
        embedding_model: Any,
        ner_model: Any | None = None,
        classifier: Any | None = None,
        qdrant_store: Any = None,
        ocr_engine: Any | None = None,
        clip_model: Any | None = None,
        chunk_size: int = 2048,
        chunk_overlap: int = 200,
        sentence_aware: bool = True,
        batch_size: int = 100,
        max_workers: int = 4,
        enable_ner: bool = True,
        enable_classifier: bool = False,
        enable_code_detection: bool = True,
        enable_image_extraction: bool = True,
        use_multivector: bool = True,
        csv_path: Optional[str] = None,
        watchlist_manager: Any | None = None,
        decay_manager: Any | None = None,
        playbook_runner: Any | None = None,
        dedup_threshold: int = 5,
    ) -> None:
        """Initialize the ingestor with all components.

        Args:
            embedding_model: EmbeddingModel instance for text embeddings.
            ner_model: NERModel instance (or None if NER disabled).
            classifier: Classifier instance (or None if classification disabled).
            qdrant_store: QdrantStore instance for database operations.
            ocr_engine: OCREngine instance (or None if OCR disabled).
            clip_model: CLIPModel instance (or None if CLIP disabled).
            chunk_size: Text chunk size in characters.
            chunk_overlap: Chunk overlap in characters.
            sentence_aware: Use sentence-aware chunking.
            batch_size: Batch size for Qdrant upserts.
            max_workers: Maximum number of worker threads.
            enable_ner: Whether to run NER on chunks.
            enable_classifier: Whether to run text classification.
            enable_code_detection: Whether to detect code snippets.
            enable_image_extraction: Whether to extract and process images.
            use_multivector: Use multi-vector (named vectors) collections.
            csv_path: Optional path to export ingestion results to CSV.
        """
        self._embedding_model = embedding_model
        self._ner_model = ner_model
        self._classifier = classifier
        self._qdrant_store = qdrant_store
        self._ocr_engine = ocr_engine
        self._clip_model = clip_model
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        self._sentence_aware = sentence_aware
        self._batch_size = batch_size
        self._max_workers = max_workers
        self._enable_ner = enable_ner
        self._enable_classifier = enable_classifier
        self._enable_code_detection = enable_code_detection
        self._enable_image_extraction = enable_image_extraction
        self._use_multivector = use_multivector
        self._csv_path = csv_path
        self._watchlist_manager = watchlist_manager
        self._decay_manager = decay_manager
        self._playbook_runner = playbook_runner
        self._dedup_threshold = dedup_threshold
        self._csv_lock = threading.Lock()
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal the ingestion to stop gracefully."""
        self._stop_event.set()

    def process_document(self, data_model: DataModel, collection_name: str, source: str) -> str:
        """Ingest an already-normalized document — e.g. one pulled SIEM/EDR
        detection — through the same collection-ensure / embed / upsert /
        watchlist-and-playbook path as file and feed ingestion.

        This is the mechanism that makes pulled detections first-class
        Black Onyx documents (searchable, graphable, case-linkable,
        watchlist-matched, auto-enrichable) instead of a parallel alert table:
        it does exactly what `process_text_file` does *after* extraction —
        skipping only the file-read/chunk step, since the caller (a
        `DetectionConnector.normalize()`) has already produced one complete
        `DataModel` rather than a file to split into many.

        Returns the Qdrant point ID as a string.
        """
        if self._qdrant_store:
            text_dim = self._embedding_model.get_embedding_dim()
            clip_dim = self._clip_model.get_embedding_dim() if self._clip_model else 512
            self._qdrant_store.ensure_collection(
                collection_name=collection_name,
                text_vector_size=text_dim,
                clip_vector_size=clip_dim,
                use_multivector=self._use_multivector,
            )

        text = (data_model.body_text or data_model.title or "").strip()
        embedding = self._embedding_model.encode_single(text)
        vector: list[float] | dict[str, list[float]]
        vector = {"text": embedding} if self._use_multivector else embedding

        # Keyed on source_file (e.g. "connector:falcon-prod:abc123"), not a
        # random id, so re-polling the same upstream detection upserts the
        # same point instead of duplicating it — the same idempotency
        # `stable_id` already gives filepath-based ingestion.
        key = data_model.source_file or source
        point_id = self._qdrant_store.stable_id(key, 0) if self._qdrant_store else 0
        payload = data_model.model_dump()
        if self._qdrant_store:
            self._qdrant_store.upsert_single(collection_name, point_id, vector, payload)
        self._observe_iocs(payload, collection_name, str(point_id), source)
        return str(point_id)

    def process_directory(
        self,
        directory: str,
        collection_name: str,
        progress_tracker: Optional[ProgressTracker] = None,
        checkpoint_manager: Optional[CheckpointManager] = None,
    ) -> dict[str, Any]:
        """Process all files in a directory.

        Walks the directory tree, identifies text and image files, and processes
        them using ThreadPoolExecutor. NER calls are serialized via the NERModel's
        internal lock.

        Args:
            directory: Root directory to process.
            collection_name: Qdrant collection to upsert into.
            progress_tracker: Optional ProgressTracker for progress updates.
            checkpoint_manager: Optional CheckpointManager for resume support.

        Returns:
            Dict with ingestion statistics: total_files, processed, errors, total_chunks.
        """
        self._stop_event.clear()

        # Ensure collection exists
        if self._qdrant_store:
            text_dim = self._embedding_model.get_embedding_dim()
            clip_dim = self._clip_model.get_embedding_dim() if self._clip_model else 512
            self._qdrant_store.ensure_collection(
                collection_name=collection_name,
                text_vector_size=text_dim,
                clip_vector_size=clip_dim,
                use_multivector=self._use_multivector,
            )

        # Collect all files
        all_files: list[str] = []
        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                file_type = detect_file_type(filepath)
                if file_type != FileType.UNKNOWN or is_image_file(filepath):
                    all_files.append(filepath)

        total = len(all_files)
        logger.info(f"Found {total} files to process in {directory}")

        if progress_tracker:
            progress_tracker.set_total(total)

        # Start ingestion run in checkpoint
        run_id = str(uuid.uuid4())
        if checkpoint_manager:
            checkpoint_manager.start_run(run_id, directory, collection_name, total)

        processed = 0
        errors = 0
        total_chunks = 0

        # Process files with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {
                executor.submit(
                    self._process_file_wrapper,
                    filepath,
                    collection_name,
                    progress_tracker,
                    checkpoint_manager,
                ): filepath
                for filepath in all_files
            }

            for future in as_completed(futures):
                if self._stop_event.is_set():
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break

                filepath = futures[future]
                try:
                    result = future.result()
                    if result["status"] == "done":
                        processed += 1
                        total_chunks += result.get("chunks", 0)
                    elif result["status"] == "error":
                        errors += 1
                        processed += 1
                    elif result["status"] == "skipped":
                        processed += 1
                except Exception as e:
                    logger.error(f"Thread execution error for {filepath}: {e}")
                    errors += 1
                    processed += 1

        # Complete run in checkpoint
        if checkpoint_manager:
            checkpoint_manager.complete_run(run_id, processed)

        if progress_tracker:
            progress_tracker.on_ingest_complete()

        stats = {
            "total_files": total,
            "processed": processed,
            "errors": errors,
            "total_chunks": total_chunks,
            "stopped": self._stop_event.is_set(),
        }
        logger.info(f"Ingestion complete: {stats}")
        return stats

    def _process_file_wrapper(
        self,
        filepath: str,
        collection_name: str,
        progress_tracker: Optional[ProgressTracker],
        checkpoint_manager: Optional[CheckpointManager],
    ) -> dict[str, Any]:
        """Wrapper that handles progress tracking and error handling around process_file."""
        if self._stop_event.is_set():
            return {"status": "skipped", "filepath": filepath, "chunks": 0}

        start_time = time.time()
        if progress_tracker:
            progress_tracker.on_file_start(filepath)

        try:
            chunks = self.process_file(filepath, collection_name, checkpoint_manager)
            duration_ms = (time.time() - start_time) * 1000
            if progress_tracker:
                progress_tracker.on_file_done(filepath, chunks, duration_ms)
            return {"status": "done", "filepath": filepath, "chunks": chunks}
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error processing {filepath}: {error_msg}")
            if progress_tracker:
                progress_tracker.on_file_error(filepath, error_msg)
            return {"status": "error", "filepath": filepath, "error": error_msg, "chunks": 0}

    def process_file(
        self,
        filepath: str,
        collection_name: str,
        checkpoint_manager: Optional[CheckpointManager] = None,
    ) -> int:
        """Process a single file — routes to text or image processing.

        Args:
            filepath: Path to the file.
            collection_name: Qdrant collection name.
            checkpoint_manager: Optional checkpoint manager.

        Returns:
            Number of chunks/points uploaded.
        """
        if is_image_file(filepath):
            return self.process_image_file(filepath, collection_name, checkpoint_manager)

        file_type = detect_file_type(filepath)
        if file_type == FileType.PDF and self._enable_image_extraction:
            # Process PDF: extract text AND embedded images
            text_chunks = self.process_text_file(filepath, collection_name, checkpoint_manager)
            # Also extract embedded images from the PDF
            image_chunks = self.process_pdf_images(filepath, collection_name, checkpoint_manager)
            return text_chunks + image_chunks

        return self.process_text_file(filepath, collection_name, checkpoint_manager)

    def process_text_file(
        self,
        filepath: str,
        collection_name: str,
        checkpoint_manager: Optional[CheckpointManager] = None,
    ) -> int:
        """Process a text-based file: extract → chunk → embed → NER → upsert.

        Args:
            filepath: Path to the file.
            collection_name: Qdrant collection name.
            checkpoint_manager: Optional checkpoint manager.

        Returns:
            Number of chunks uploaded.
        """
        # Extract text
        text = extract_text_from_file(filepath)
        if not text or not text.strip():
            logger.warning(f"Extracted text is empty for file: {filepath}")
            return 0

        # Clean text
        cleaned_text = re.sub(r"\s+", " ", text).strip()

        # Chunk
        chunks = chunk_text_auto(
            cleaned_text,
            chunk_size=self._chunk_size,
            overlap=self._chunk_overlap,
            sentence_aware=self._sentence_aware,
        )

        if not chunks:
            return 0

        logger.info(f"File '{filepath}' split into {len(chunks)} chunks")

        # Extract HTML metadata once (from the full text, not per chunk)
        html_metadata: dict[str, Any] = {}
        file_type = detect_file_type(filepath)
        if file_type == FileType.HTML:
            html_metadata = extract_metadata_from_html(text)

        # Process chunks in batches
        uploaded = 0
        batch_size = min(self._batch_size, 10)  # Smaller batches for embedding

        for i in range(0, len(chunks), batch_size):
            if self._stop_event.is_set():
                break

            batch_chunks = chunks[i : i + batch_size]
            batch_indices = list(range(i, i + len(batch_chunks)))

            # Skip already-processed chunks
            to_process: list[tuple[int, str]] = []
            for idx, chunk in zip(batch_indices, batch_chunks):
                if checkpoint_manager and checkpoint_manager.is_processed(filepath, idx, collection_name):
                    logger.debug(f"Skipping already-processed chunk {idx} of {filepath}")
                    continue
                to_process.append((idx, chunk))

            if not to_process:
                continue

            # Generate embeddings for the batch
            chunk_texts = [c for _, c in to_process]
            embeddings = self._embedding_model.encode(chunk_texts)

            # Process each chunk
            points: list[PointStruct] = []
            for (chunk_idx, chunk_text), embedding in zip(to_process, embeddings):
                if self._stop_event.is_set():
                    break

                # Build DataModel payload
                data_model = self._build_payload(
                    chunk_text=chunk_text,
                    filepath=filepath,
                    chunk_idx=chunk_idx,
                    total_chunks=len(chunks),
                    html_metadata=html_metadata,
                    full_text=text,
                )

                # Generate stable point ID
                point_id = self._qdrant_store.stable_id(filepath, chunk_idx)

                # Build vector dict for multi-vector, or plain list for single vector
                if self._use_multivector:
                    vector: list[float] | dict[str, list[float]] = {"text": embedding}
                else:
                    vector = embedding

                points.append(
                    PointStruct(id=point_id, vector=cast(Any, vector), payload=data_model.model_dump())
                )

            # Batch upsert
            if points and self._qdrant_store:
                self._qdrant_store.upsert(collection_name, points)
                logger.debug(f"Upserted {len(points)} chunks from {filepath}")
                for (chunk_idx, _), point in zip(to_process, points):
                    if checkpoint_manager:
                        checkpoint_manager.mark_processed(filepath, chunk_idx, collection_name)
                    payload = cast(dict[str, Any], point.payload or {})
                    self._observe_iocs(payload, collection_name, str(point.id), filepath)
                    if self._csv_path:
                        self._write_csv_payload(filepath, chunk_idx, payload)
                    uploaded += 1

        logger.info(f"Uploaded {uploaded} chunks for file: {filepath}")
        return uploaded

    def process_image_file(
        self,
        filepath: str,
        collection_name: str,
        checkpoint_manager: Optional[CheckpointManager] = None,
    ) -> int:
        """Process an image file: EXIF + OCR + CLIP + metadata → upsert.

        Args:
            filepath: Path to the image file.
            collection_name: Qdrant collection name.
            checkpoint_manager: Optional checkpoint manager.

        Returns:
            1 if uploaded, 0 if skipped or failed.
        """
        if checkpoint_manager and checkpoint_manager.is_processed(filepath, 0, collection_name):
            logger.debug(f"Skipping already-processed image: {filepath}")
            return 0

        # Process the image through the full pipeline
        image_data = process_image(
            image_path=filepath,
            ocr_engine=self._ocr_engine,
            clip_model=self._clip_model,
        )
        if self._qdrant_store and image_data.get("image_hash"):
            duplicate = self._qdrant_store.find_similar_image_hash(
                collection_name, image_data["image_hash"], self._dedup_threshold
            )
            if duplicate is not None:
                logger.info("Skipping perceptual duplicate image %s (matches %s)", filepath, duplicate.id)
                if checkpoint_manager:
                    checkpoint_manager.mark_processed(filepath, 0, collection_name)
                return 0

        # Generate text embedding from OCR text (if available)
        text_vector: list[float] = []
        if image_data.get("ocr_text"):
            text_vector = self._embedding_model.encode_single(image_data["ocr_text"])

        # Extract metadata from OCR text
        ocr_metadata: dict[str, Any] = {}
        if image_data.get("ocr_text"):
            ocr_metadata = extract_metadata_from_text(image_data["ocr_text"])

        # Build DataModel
        data_model = DataModel(
            source_file=filepath,
            chunk_index=0,
            total_chunks=1,
            payload_type="image",
            body_text=image_data.get("ocr_text"),
            ocr_text=image_data.get("ocr_text"),
            image_width=image_data.get("image_width"),
            image_height=image_data.get("image_height"),
            image_format=image_data.get("image_format"),
            image_hash=image_data.get("image_hash"),
            exif_data=image_data.get("exif_data"),
            gps_latitude=image_data.get("gps_latitude"),
            gps_longitude=image_data.get("gps_longitude"),
            camera_make=image_data.get("camera_make"),
            camera_model=image_data.get("camera_model"),
            capture_time=image_data.get("capture_time"),
            embedding_model=self._clip_model.model_name if self._clip_model else None,
            embedding_type="clip_vision",
        )

        # Merge OCR metadata
        if ocr_metadata:
            data_model.merge_metadata(ocr_metadata)
            crypto_fields = map_crypto_to_fields(ocr_metadata.get("cryptos", {}))
            for field_name, addresses in crypto_fields.items():
                current = getattr(data_model, field_name) or []
                for addr in addresses:
                    if addr not in current:
                        current.append(addr)
                setattr(data_model, field_name, current)

        # Generate stable point ID
        point_id = self._qdrant_store.stable_id(filepath, 0)

        # Build vector dict
        clip_vector = image_data.get("clip_vector")
        if self._use_multivector:
            named_vectors: dict[str, list[float]] = {}
            if clip_vector:
                named_vectors["clip"] = clip_vector
            if text_vector:
                named_vectors["text"] = text_vector
            vector: list[float] | dict[str, list[float]] = named_vectors
        else:
            # Use clip vector if available, otherwise text vector
            vector = clip_vector if clip_vector else text_vector

        if not vector:
            logger.warning(f"No embeddings generated for image: {filepath}")
            return 0

        # Upsert
        self._qdrant_store.upsert_single(
            collection_name=collection_name,
            point_id=point_id,
            vector=vector,
            payload=data_model.model_dump(),
        )
        self._observe_iocs(data_model.model_dump(), collection_name, str(point_id), filepath)

        # Mark as processed
        if checkpoint_manager:
            checkpoint_manager.mark_processed(filepath, 0, collection_name)

        logger.info(f"Uploaded image: {filepath}")
        return 1

    def process_pdf_images(
        self,
        pdf_path: str,
        collection_name: str,
        checkpoint_manager: Optional[CheckpointManager] = None,
    ) -> int:
        """Extract and process embedded images from a PDF.

        Args:
            pdf_path: Path to the PDF file.
            collection_name: Qdrant collection name.
            checkpoint_manager: Optional checkpoint manager.

        Returns:
            Number of images processed.
        """
        if not self._enable_image_extraction:
            return 0

        # Extract images to a temp directory
        import tempfile

        pdf_name = os.path.splitext(os.path.basename(pdf_path))[0]
        output_dir = os.path.join(tempfile.gettempdir(), "black_onyx_images", pdf_name)
        image_paths = extract_images_from_pdf(pdf_path, output_dir)

        if not image_paths:
            return 0

        logger.info(f"Extracted {len(image_paths)} images from PDF: {pdf_path}")

        count = 0
        for img_idx, img_path in enumerate(image_paths):
            if self._stop_event.is_set():
                break

            # Use a unique chunk index for each image
            chunk_idx = 10000 + img_idx  # Offset to avoid collision with text chunks

            if checkpoint_manager and checkpoint_manager.is_processed(pdf_path, chunk_idx, collection_name):
                continue

            # Process the extracted image
            image_data = process_image(
                image_path=img_path,
                ocr_engine=self._ocr_engine,
                clip_model=self._clip_model,
            )

            # Generate text embedding from OCR text
            text_vector: list[float] = []
            if image_data.get("ocr_text"):
                text_vector = self._embedding_model.encode_single(image_data["ocr_text"])

            # Build DataModel pointing back to the parent PDF
            data_model = DataModel(
                source_file=pdf_path,
                chunk_index=chunk_idx,
                total_chunks=len(image_paths),
                payload_type="image",
                body_text=image_data.get("ocr_text"),
                ocr_text=image_data.get("ocr_text"),
                image_width=image_data.get("image_width"),
                image_height=image_data.get("image_height"),
                image_format=image_data.get("image_format"),
                image_hash=image_data.get("image_hash"),
                exif_data=image_data.get("exif_data"),
                gps_latitude=image_data.get("gps_latitude"),
                gps_longitude=image_data.get("gps_longitude"),
                camera_make=image_data.get("camera_make"),
                camera_model=image_data.get("camera_model"),
                capture_time=image_data.get("capture_time"),
                embedding_model=self._clip_model.model_name if self._clip_model else None,
                embedding_type="clip_vision",
            )

            # Extract metadata from OCR text
            if image_data.get("ocr_text"):
                ocr_metadata = extract_metadata_from_text(image_data["ocr_text"])
                data_model.merge_metadata(ocr_metadata)
                crypto_fields = map_crypto_to_fields(ocr_metadata.get("cryptos", {}))
                for field_name, addresses in crypto_fields.items():
                    current = getattr(data_model, field_name) or []
                    for addr in addresses:
                        if addr not in current:
                            current.append(addr)
                    setattr(data_model, field_name, current)

            point_id = self._qdrant_store.stable_id(pdf_path, chunk_idx)

            clip_vector = image_data.get("clip_vector")
            if self._use_multivector:
                named_vectors: dict[str, list[float]] = {}
                if clip_vector:
                    named_vectors["clip"] = clip_vector
                if text_vector:
                    named_vectors["text"] = text_vector
                vector: list[float] | dict[str, list[float]] = named_vectors
            else:
                vector = clip_vector if clip_vector else text_vector

            if not vector:
                continue

            self._qdrant_store.upsert_single(
                collection_name=collection_name,
                point_id=point_id,
                vector=vector,
                payload=data_model.model_dump(),
            )

            if checkpoint_manager:
                checkpoint_manager.mark_processed(pdf_path, chunk_idx, collection_name)

            count += 1

        # Clean up temp images
        try:
            import shutil
            shutil.rmtree(output_dir, ignore_errors=True)
        except Exception as exc:
            logger.debug("Temporary image cleanup failed: %s", type(exc).__name__)

        logger.info(f"Processed {count} images from PDF: {pdf_path}")
        return count

    def _build_payload(
        self,
        chunk_text: str,
        filepath: str,
        chunk_idx: int,
        total_chunks: int,
        html_metadata: dict[str, Any],
        full_text: str,
    ) -> DataModel:
        """Build a DataModel payload for a text chunk.

        Args:
            chunk_text: The text chunk content.
            filepath: Source file path.
            chunk_idx: Chunk index within the file.
            total_chunks: Total number of chunks in the file.
            html_metadata: Pre-extracted HTML metadata (empty dict for non-HTML).
            full_text: Full text of the source file (for metadata extraction on non-HTML).

        Returns:
            DataModel instance with all extracted data.
        """
        # Start with basic fields
        data_model = DataModel(
            source_file=filepath,
            chunk_index=chunk_idx,
            total_chunks=total_chunks,
            payload_type="text",
            body_text=chunk_text,
            title=html_metadata.get("title"),
            embedding_model=self._embedding_model.model_name,
            embedding_type="text",
        )

        # Merge HTML metadata if available
        if html_metadata:
            data_model.merge_metadata(html_metadata)
            # Map crypto addresses to their specific fields
            crypto_fields = map_crypto_to_fields(html_metadata.get("cryptos", {}))
            for field_name, addresses in crypto_fields.items():
                current = getattr(data_model, field_name) or []
                for addr in addresses:
                    if addr not in current:
                        current.append(addr)
                setattr(data_model, field_name, current)
        else:
            # For non-HTML files, extract metadata from the chunk text
            text_metadata = extract_metadata_from_text(chunk_text)
            data_model.merge_metadata(text_metadata)
            crypto_fields = map_crypto_to_fields(text_metadata.get("cryptos", {}))
            for field_name, addresses in crypto_fields.items():
                current = getattr(data_model, field_name) or []
                for addr in addresses:
                    if addr not in current:
                        current.append(addr)
                setattr(data_model, field_name, current)

        # NER extraction
        if self._enable_ner and self._ner_model:
            entities = self._ner_model.predict(chunk_text)
            if entities:
                ner_fields = self._ner_model.map_to_datamodel_fields(entities)
                for field_name, values in ner_fields.items():
                    current = getattr(data_model, field_name) or []
                    for v in values:
                        if v not in current:
                            current.append(v)
                    setattr(data_model, field_name, current)
                # Store raw NER entities as "label:text" strings
                ner_entity_strings = [f"{e['label']}:{e['text']}" for e in entities]
                data_model.ner_entities = ner_entity_strings

        # IOC extraction
        from black_onyx.extraction.ioc import extract_iocs
        iocs = extract_iocs(chunk_text)
        if iocs.ipv4:
            data_model.ip_addresses.extend(iocs.ipv4)
        if iocs.ipv6:
            data_model.ip_addresses.extend(iocs.ipv6)
        if iocs.urls:
            data_model.urls = iocs.urls
        if iocs.md5:
            data_model.md5_hashes = iocs.md5
        if iocs.sha1:
            data_model.sha1_hashes = iocs.sha1
        if iocs.sha256:
            data_model.sha256_hashes = iocs.sha256
        if iocs.sha512:
            data_model.sha512_hashes = iocs.sha512
        if iocs.cves:
            data_model.cve_ids = iocs.cves
        if iocs.domains:
            data_model.domains = iocs.domains
        if iocs.cidr_ranges:
            data_model.cidr_ranges = iocs.cidr_ranges
        if iocs.mac_addresses:
            data_model.mac_addresses = iocs.mac_addresses
        if iocs.asns:
            data_model.asns = iocs.asns
        if iocs.cpes:
            data_model.cpes = iocs.cpes
        if iocs.jarm_fingerprints:
            data_model.jarm_fingerprints = iocs.jarm_fingerprints
        if iocs.mitre_techniques:
            data_model.mitre_techniques = iocs.mitre_techniques
        if iocs.mitre_tactics:
            data_model.mitre_tactics = iocs.mitre_tactics
        if iocs.yara_rules:
            data_model.yara_rules = iocs.yara_rules
        if iocs.sigma_rules:
            data_model.sigma_rules = iocs.sigma_rules
        if iocs.user_agents:
            data_model.user_agents = iocs.user_agents
        if iocs.defanged_iocs:
            data_model.defanged_iocs = iocs.defanged_iocs

        # Code detection
        if self._enable_code_detection:
            code_snippets, code_languages = detect_code_snippets(chunk_text)
            if code_snippets:
                data_model.code_snippets = code_snippets
                data_model.code_languages = code_languages

        # Classification
        if self._enable_classifier and self._classifier:
            classification = self._classifier.classify(chunk_text)
            data_model.classification = classification.get("label")
            data_model.classification_score = classification.get("score")

        return data_model

    def _write_csv(self, filepath: str, chunk_idx: int, data_model: DataModel) -> None:
        """Write a row to the CSV output file.

        Args:
            filepath: Source file path.
            chunk_idx: Chunk index.
            data_model: DataModel with extracted data.
        """
        import csv as csv_module

        if not self._csv_path:
            return
        try:
            file_exists = os.path.isfile(self._csv_path)
            with self._csv_lock:
                with open(self._csv_path, "a", newline="", encoding="utf-8") as csvfile:
                    writer = csv_module.writer(csvfile)
                    if not file_exists:
                        writer.writerow(["filepath", "chunk_index", "classification", "title", "emails"])
                    writer.writerow([
                        filepath,
                        chunk_idx,
                        data_model.classification or "",
                        data_model.title or "",
                        ",".join(data_model.emails),
                    ])
        except Exception as e:
            logger.debug(f"CSV write failed: {e}")

    def _write_csv_payload(self, filepath: str, chunk_idx: int, payload: dict[str, Any]) -> None:
        """Serialize an already-committed payload to CSV."""
        self._write_csv(filepath, chunk_idx, DataModel(**payload))

    def _observe_iocs(self, payload: dict[str, Any], collection: str, point_id: str, source: str) -> None:
        """Connect successful ingestion to watchlist alerting, decay tracking, and
        the playbook engine.

        The webhook-ingest route (`/api/v1/webhooks/events`) has always fired
        `playbook_runner.handle_trigger("watchlist_alert", ...)` on a match; this
        path — every ordinary file and feed ingestion — did not, so a playbook
        wired to `watchlist_alert` (e.g. the seeded auto-enrich playbook) only
        ever ran for webhook-sourced IOCs. Closing that asymmetry here is what
        makes "enrich on watchlist match" apply to normal ingestion too.
        """
        field_map = {
            "ip_addresses": "ip", "domains": "domain",
            "urls": "url", "md5_hashes": "md5", "sha1_hashes": "sha1",
            "sha256_hashes": "sha256", "sha512_hashes": "sha512", "cve_ids": "cve",
        }
        iocs = {
            ioc_type: payload.get(field, [])
            for field, ioc_type in field_map.items()
            if payload.get(field)
        }
        if self._decay_manager and iocs:
            self._decay_manager.record_sightings_batch(iocs, source=source)
        if self._watchlist_manager and iocs:
            alerts = self._watchlist_manager.check_iocs(
                iocs, collection=collection, point_id=point_id, context=source,
            )
            if alerts and self._playbook_runner:
                # Only the indicators that actually matched a watchlist — not
                # every indicator in the document. PlaybookRunner._collect_iocs
                # prefers context["iocs"], so passing the full extraction here
                # would make one watchlist hit in a 300-IOC threat report
                # enrich all 300 against every configured provider, which is
                # exactly the paid-API quota burn the enrichment.auto_enrich_
                # on_match setting promises to avoid. Deduplicated because a
                # single indicator can appear on several watchlists.
                ioc_list = list({
                    (alert.get("ioc_type"), alert.get("ioc_value")): {
                        "ioc_type": alert.get("ioc_type"),
                        "ioc_value": alert.get("ioc_value"),
                    }
                    for alert in alerts
                    if alert.get("ioc_type") and alert.get("ioc_value")
                }.values())
                try:
                    # Safe: _observe_iocs is only ever reached via
                    # process_text_file/process_image_file, which in turn are
                    # only invoked either inside process_directory's
                    # ThreadPoolExecutor workers, or (for feed polling) via
                    # asyncio.to_thread — never on the FastAPI event-loop
                    # thread — so there is no running loop here to collide with.
                    asyncio.run(self._playbook_runner.handle_trigger(
                        "watchlist_alert",
                        {
                            "alerts": alerts,
                            "iocs": ioc_list,
                            "source": source,
                            "collection": collection,
                            "point_id": point_id,
                        },
                    ))
                except Exception:
                    logger.exception("Playbook watchlist_alert trigger failed")
