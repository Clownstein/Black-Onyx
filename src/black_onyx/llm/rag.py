"""RAG engine — retrieves relevant chunks from Qdrant and augments LLM prompts."""

from __future__ import annotations

import logging
from typing import Any

from black_onyx.llm.base import ChatMessage, ChatResponse, LLMProvider, RetrievedChunk

logger = logging.getLogger(__name__)


class RAGEngine:
    """Retrieval-Augmented Generation engine.

    Retrieves relevant chunks from one or more Qdrant collections using
    semantic search, then augments the LLM prompt with the retrieved context.
    Supports neighboring chunk context expansion.
    """

    def __init__(
        self,
        llm_provider: LLMProvider,
        embedding_model: Any,
        qdrant_store: Any,
        collections: list[str] | None = None,
        top_k: int = 8,
        score_threshold: float = 0.5,
        chunk_context_window: int = 2,
        system_prompt: str = "",
    ) -> None:
        """Initialize the RAG engine.

        Args:
            llm_provider: LLM provider for generating responses.
            embedding_model: Embedding model for query encoding.
            qdrant_store: Qdrant store for vector search.
            collections: List of collections to search across.
            top_k: Number of top results to retrieve per collection.
            score_threshold: Minimum similarity score for results.
            chunk_context_window: Number of neighboring chunks to include
                                  for context expansion (0 = disabled).
            system_prompt: System prompt for the LLM.
        """
        self._llm = llm_provider
        self._embedding_model = embedding_model
        self._qdrant = qdrant_store
        self._collections = collections or []
        self._top_k = top_k
        self._score_threshold = score_threshold
        self._chunk_context_window = chunk_context_window
        self._system_prompt = system_prompt

    def retrieve(
        self,
        query: str,
        collections: list[str] | None = None,
        top_k: int | None = None,
        score_threshold: float | None = None,
    ) -> list[RetrievedChunk]:
        """Retrieve relevant chunks for a query.

        Searches across all configured collections (or a specified subset),
        merges results, and sorts by score.

        Args:
            query: Search query text.
            collections: Override collections to search. If None, uses configured.
            top_k: Override top_k. If None, uses configured.
            score_threshold: Override score threshold.

        Returns:
            List of RetrievedChunk objects, sorted by score descending.
        """
        cols = collections or self._collections
        k = top_k if top_k is not None else self._top_k
        threshold = score_threshold if score_threshold is not None else self._score_threshold

        if not cols:
            logger.warning("No collections configured for RAG retrieval")
            return []

        # Encode the query
        query_vector = self._embedding_model.encode_single(query)
        if not query_vector:
            logger.error("Failed to encode query for RAG retrieval")
            return []

        all_results: list[RetrievedChunk] = []

        for collection in cols:
            try:
                results = self._qdrant.search(
                    collection_name=collection,
                    query_vector=query_vector,
                    limit=k,
                    score_threshold=threshold,
                    using="text",  # Use the text named vector
                    with_payload=True,
                    with_vectors=False,
                )
                for r in results:
                    chunk = RetrievedChunk(
                        id=r.id,
                        score=r.score,
                        payload=r.payload or {},
                        collection=collection,
                    )
                    all_results.append(chunk)
            except Exception as e:
                logger.error(f"RAG retrieval error in collection '{collection}': {e}")

        # Sort by score descending
        all_results.sort(key=lambda x: x.score, reverse=True)

        # Apply context window expansion
        if self._chunk_context_window > 0:
            all_results = self._expand_context(all_results)

        return all_results

    def _expand_context(self, chunks: list[RetrievedChunk]) -> list[RetrievedChunk]:
        """Expand retrieved chunks with neighboring chunks for context.

        For each retrieved chunk, fetches the previous and next N chunks
        from the same source file (if available in Qdrant).

        Args:
            chunks: Initially retrieved chunks.

        Returns:
            Expanded list of chunks (deduplicated, sorted by score).
        """
        if not chunks:
            return chunks

        expanded: list[RetrievedChunk] = []
        seen_ids: set = set()

        for chunk in chunks:
            # Add the original chunk
            if chunk.id not in seen_ids:
                expanded.append(chunk)
                seen_ids.add(chunk.id)

            # Try to fetch neighboring chunks
            source_file = chunk.payload.get("source_file")
            current_idx = chunk.payload.get("chunk_index")
            if not source_file or current_idx is None:
                continue

            for offset in range(-self._chunk_context_window, self._chunk_context_window + 1):
                if offset == 0:
                    continue
                neighbor_idx = current_idx + offset
                if neighbor_idx < 0:
                    continue

                # Generate the neighbor's point ID
                neighbor_id = self._qdrant.stable_id(source_file, neighbor_idx)
                if neighbor_id in seen_ids:
                    continue

                try:
                    point = self._qdrant.get_point(chunk.collection, neighbor_id)
                    if point and point.payload:
                        neighbor = RetrievedChunk(
                            id=point.id,
                            score=0.0,  # Neighbors don't have a relevance score
                            payload=point.payload,
                            collection=chunk.collection,
                        )
                        expanded.append(neighbor)
                        seen_ids.add(neighbor_id)
                except Exception as exc:
                    logger.debug("RAG neighbor unavailable: %s", type(exc).__name__)

        return expanded

    def build_context_prompt(
        self,
        query: str,
        chunks: list[RetrievedChunk],
        max_context_chars: int = 12000,
    ) -> str:
        """Build the augmented prompt with retrieved context.

        Args:
            query: User's original query.
            chunks: Retrieved chunks to include as context.
            max_context_chars: Maximum total characters for context.

        Returns:
            Formatted prompt string with context and query.
        """
        if not chunks:
            return query

        context_parts: list[str] = []
        total_chars = 0

        for i, chunk in enumerate(chunks):
            source = chunk.payload.get("source_file", "unknown")
            chunk_idx = chunk.payload.get("chunk_index", 0)
            body_text = chunk.payload.get("body_text", "")

            if not body_text:
                continue

            # Truncate individual chunks if needed
            remaining = max_context_chars - total_chars
            if remaining <= 0:
                break
            if len(body_text) > remaining:
                body_text = body_text[:remaining] + "..."

            entry = f"[Source: {source}, Chunk: {chunk_idx}, Score: {chunk.score:.3f}]\n{body_text}"
            context_parts.append(entry)
            total_chars += len(entry)

        context = "\n\n---\n\n".join(context_parts)

        prompt = f"""Based on the following retrieved context, answer the user's question.
If the context doesn't contain enough information, say so clearly.

=== RETRIEVED CONTEXT ===
{context}

=== USER QUESTION ===
{query}
"""
        return prompt

    def chat(
        self,
        query: str,
        history: list[ChatMessage] | None = None,
        collections: list[str] | None = None,
    ) -> tuple[ChatResponse, list[RetrievedChunk]]:
        """Run a RAG-augmented chat completion.

        Retrieves relevant context, builds the augmented prompt, and sends
        it to the LLM provider.

        Args:
            query: User's query.
            history: Optional chat history (previous messages).
            collections: Override collections to search.

        Returns:
            Tuple of (ChatResponse, list of RetrievedChunks used as context).
        """
        # Retrieve relevant chunks
        chunks = self.retrieve(query, collections=collections)

        # Build the augmented prompt
        augmented_prompt = self.build_context_prompt(query, chunks)

        # Build message list with history
        messages: list[ChatMessage] = []
        if history:
            messages.extend(history)
        messages.append(ChatMessage(role="user", content=augmented_prompt))

        # Generate response
        response = self._llm.chat(
            messages=messages,
            system_prompt=self._system_prompt,
        )

        return response, chunks

    async def chat_stream(
        self,
        query: str,
        history: list[ChatMessage] | None = None,
        collections: list[str] | None = None,
    ):
        """Stream a RAG-augmented chat completion.

        First retrieves context (synchronous), then streams the LLM response.

        Args:
            query: User's query.
            history: Optional chat history.
            collections: Override collections to search.

        Yields:
            Either ("context", RetrievedChunk) for each retrieved chunk,
            or ("token", str) for each generated token.
        """
        # Retrieve relevant chunks first
        chunks = self.retrieve(query, collections=collections)

        # Yield context chunks so the UI can display sources
        for chunk in chunks:
            yield ("context", chunk)

        # Build the augmented prompt
        augmented_prompt = self.build_context_prompt(query, chunks)

        # Build message list with history
        messages: list[ChatMessage] = []
        if history:
            messages.extend(history)
        messages.append(ChatMessage(role="user", content=augmented_prompt))

        # Stream the LLM response
        async for token in self._llm.chat_stream(
            messages=messages,
            system_prompt=self._system_prompt,
        ):
            yield ("token", token)

    def update_config(
        self,
        collections: list[str] | None = None,
        top_k: int | None = None,
        score_threshold: float | None = None,
        system_prompt: str | None = None,
    ) -> None:
        """Update RAG configuration parameters.

        Args:
            collections: New collections list.
            top_k: New top_k value.
            score_threshold: New score threshold.
            system_prompt: New system prompt.
        """
        if collections is not None:
            self._collections = collections
        if top_k is not None:
            self._top_k = top_k
        if score_threshold is not None:
            self._score_threshold = score_threshold
        if system_prompt is not None:
            self._system_prompt = system_prompt
