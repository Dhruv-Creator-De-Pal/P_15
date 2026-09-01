"""Lightweight in-memory vector store over captured packets.

Builds character-TF vectors from each packet's human-readable summary and
retrieves the most contextually relevant packets for a query using cosine
similarity. The retriever follows the LangChain ``invoke`` contract so the
existing ``ai_engine.query_ai`` pipeline can consume it directly.

No external embedding model or heavy dependency is required: everything runs
locally with ``numpy`` (falling back to pure Python if unavailable).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable

try:  # pragma: no cover - numpy is optional
    import numpy as np
except Exception:  # noqa: BLE001
    np = None


_TOKEN_RE = re.compile(r"[a-zA-Z0-9]+")


def _tokens(text: str) -> list[str]:
    """Lowercase alphanumeric tokens from a piece of packet text."""
    return _TOKEN_RE.findall((text or "").lower())


def _tf_vector(tokens: Iterable[str]) -> dict[str, float]:
    """Term-frequency vector as a sparse dict of {token: count}."""
    counts = Counter(tokens)
    return {tok: count for tok, count in counts.items()}


def _normalized(vector: dict[str, float]) -> dict[str, float]:
    """Normalize a TF vector to unit length for cosine similarity."""
    norm = _norm(vector)
    if not norm:
        return {}
    return {tok: value / norm for tok, value in vector.items()}


def _norm(vector: dict[str, float]) -> float:
    return sum(v * v for v in vector.values()) ** 0.5


def _dot(a: dict[str, float], b: dict[str, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(value * b.get(tok, 0.0) for tok, value in a.items())


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    """Cosine similarity between two normalized TF vectors."""
    return _dot(a, b)


class PacketVectorStore:
    """A context-based vector store over decoded packet descriptions.

    Records are stored as keyword-searchable packets so the AI pipeline can
    retrieve the most relevant ones for a question before answering. Each
    record carries the packet hex in ``data`` so ``ai_engine._decode_records``
    can reconstruct the original Scapy packet.
    """

    def __init__(self) -> None:
        self._packets: list[dict[str, Any]] = []
        self._vectors: list[dict[str, float]] = []

    def _record_from_packet(self, packet: Any) -> dict[str, Any]:
        """Build a stored record (summary + hex) from a raw Scapy packet."""
        try:
            summary = packet.summary()
        except Exception:  # noqa: BLE001
            summary = f"Packet {len(self._packets) + 1}"
        try:
            layers = [layer.__name__ for layer in packet.layers()]
        except Exception:  # noqa: BLE001
            layers = []
        try:
            data = bytes(packet).hex()
        except Exception:  # noqa: BLE001
            data = ""
        return {"summary": summary, "layers": layers, "data": data}

    def add_packet(self, packet: Any) -> None:
        """Index one raw Scapy packet into the store."""
        record = self._record_from_packet(packet)
        self._packets.append(record)
        self._vectors.append(
            _normalized(_tf_vector(_tokens(record["summary"])))
        )

    def add_packets(self, packets: Iterable[Any]) -> int:
        """Index several raw Scapy packets; returns the count added."""
        packets = list(packets)
        for packet in packets:
            self.add_packet(packet)
        return len(packets)

    def _top_k(self, query_vector: dict[str, float], k: int) -> list[int]:
        """Indices of the k records most similar to the query vector."""
        scored: list[tuple[float, int]] = []
        for index, vector in enumerate(self._vectors):
            scored.append((_cosine(query_vector, vector), index))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [index for _, index in scored[:k]]

    def retrieve(
        self,
        query: str,
        k: int = 5,
        *,
        raw: bool = False,
    ) -> list[dict[str, Any]]:
        """Return the k most relevant packet records for ``query``.

        With ``raw=False`` (default) records are returned in the decoded shape
        produced by ``ai_engine._decode_records``; with ``raw=True`` the stored
        summary/hex records are returned.
        """
        if not self._packets:
            return []
        query_vector = _normalized(_tf_vector(_tokens(query)))
        matches = self._top_k(query_vector, max(1, k))
        records = [self._packets[index] for index in matches]
        if raw:
            return records
        return [self._decode(record) for record in records]

    def invoke(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        """LangChain-compatible retriever entry point."""
        return self.retrieve(query, k=k, raw=True)

    def __call__(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        """Callable retriever entry point (works with ``callable(retriever)``)."""
        return self.retrieve(query, k=k, raw=True)

    def _decode(self, record: dict[str, Any]) -> dict[str, Any]:
        try:
            from .snifer import parse_packet_data

            return parse_packet_data(record)
        except Exception as exc:  # noqa: BLE001
            return {
                "summary": record.get("summary", "unknown packet"),
                "layers": [],
                "readable_text": "<packet could not be decoded>",
                "decode_error": str(exc),
            }

    def __len__(self) -> int:
        return len(self._packets)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PacketVectorStore packets={len(self._packets)}>"
