"""Production AI analysis helpers for packet data."""
from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from typing import Any

from dotenv import load_dotenv

load_dotenv()
DEFAULT_MODEL = "openai:gpt-4o-mini"
SYSTEM_PROMPT = (
    "You are a careful network traffic analyst. Use only supplied packet data, "
    "separate facts from assumptions, and never claim encrypted traffic was decrypted."
)


class AIEngineError(RuntimeError):
    """Raised when an AI request cannot be completed."""


def _client() -> Any:
    try:
        import aisuite
        return aisuite.Client()
    except Exception as exc:
        raise AIEngineError("Unable to load aisuite in the active environment.") from exc


def _model_name(model: str | None) -> str:
    value = (model or os.getenv("AI_MODEL") or DEFAULT_MODEL).strip()
    if not value:
        raise ValueError("model must not be empty")
    return value


def _response_text(response: Any) -> str:
    try:
        content = response.choices[0].message.content
    except (AttributeError, IndexError, KeyError, TypeError) as exc:
        raise AIEngineError("The AI provider returned an invalid response.") from exc
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, Sequence) and not isinstance(content, (str, bytes)):
        return "".join(
            item.get("text", "") if isinstance(item, Mapping) else str(item)
            for item in content
        ).strip()
    return str(content or "").strip()


def _request(messages: list[dict[str, str]], model: str) -> str:
    try:
        response = _client().chat.completions.create(model=model, messages=messages)
        answer = _response_text(response)
    except AIEngineError:
        raise
    except Exception as exc:
        raise AIEngineError(f"AI request failed for model {model!r}.") from exc
    if not answer:
        raise AIEngineError("The AI provider returned an empty response.")
    return answer


def _packet_json(packet_context: list[dict[str, Any]]) -> str:
    if not isinstance(packet_context, list):
        raise TypeError("packet_context must be a list")
    if not all(isinstance(packet, dict) for packet in packet_context):
        raise TypeError("each packet record must be a dictionary")
    return json.dumps(packet_context, indent=2, ensure_ascii=True, default=str)


def analyze_packets(packet_context: list[dict[str, Any]], model: str | None = None) -> dict[str, Any]:
    """Analyze packets; return model, packet_count, answer, and packets."""
    selected_model = _model_name(model)
    answer = _request(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": (
                "Analyze these authorized capture records. Report protocols, "
                "visible payloads, suspicious indicators, risks, and unknowns.\\n\\n"
                f"Packet records:\\n{_packet_json(packet_context)}"
            )},
        ],
        selected_model,
    )
    return {"model": selected_model, "packet_count": len(packet_context), "answer": answer, "packets": packet_context}


def chat(message: str, history: list[dict[str, str]] | None = None, packet_context: list[dict[str, Any]] | None = None, model: str | None = None) -> dict[str, Any]:
    """Answer a dashboard question; return model, question, and answer."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")
    selected_model = _model_name(model)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history or [])
    messages.append({"role": "user", "content": f"Packet context:\\n{_packet_json(packet_context or [])}\\n\\nQuestion: {message.strip()}"})
    return {"model": selected_model, "question": message.strip(), "answer": _request(messages, selected_model)}


def dashboard_state(packet_context: list[dict[str, Any]], analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return packet rows, analysis, count, and status for a dashboard."""
    _packet_json(packet_context)
    return {"packet_count": len(packet_context), "packets": packet_context, "analysis": analysis, "status": "ready" if packet_context else "empty"}


def _retrieved_records(retriever: Any, query: str, limit: int) -> list[dict[str, Any]]:
    """Convert LangChain-style retriever results into packet dictionaries."""
    if hasattr(retriever, "invoke"):
        documents = retriever.invoke(query)
    elif hasattr(retriever, "similarity_search"):
        documents = retriever.similarity_search(query, k=limit)
    elif callable(retriever):
        documents = retriever(query)
    else:
        raise TypeError("retriever must provide invoke, similarity_search, or __call__")

    records = []
    for document in list(documents or [])[:limit]:
        if isinstance(document, dict):
            record = document
        else:
            metadata = getattr(document, "metadata", {}) or {}
            content = getattr(document, "page_content", "")
            record = metadata.get("pkt_info")
            if record is None:
                try:
                    record = json.loads(content)
                except (TypeError, json.JSONDecodeError):
                    continue
        if isinstance(record, dict) and "data" in record:
            records.append(record)
    return records


def _decode_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Decode retrieved packet hex through the sniffer's parser."""
    try:
        from .snifer import parse_packet_data
    except Exception as exc:
        raise AIEngineError("Unable to load the packet decoder.") from exc

    decoded = []
    for record in records:
        try:
            decoded.append(parse_packet_data(record))
        except (KeyError, TypeError, ValueError) as exc:
            decoded.append({
                "summary": record.get("summary", "unknown packet"),
                "layers": record.get("layers", []),
                "readable_text": "<packet could not be decoded>",
                "decode_error": str(exc),
            })
    return decoded


def query_ai(
    message: str,
    retriever: Any,
    history: list[dict[str, str]] | None = None,
    model: str | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Retrieve, decode, and answer a dashboard question.

    The retriever may be a Chroma/LangChain retriever, a vector store exposing
    ``similarity_search``, or a callable returning packet dictionaries.
    Returned keys are ``model``, ``question``, ``answer``, and ``packets``.
    """
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be a non-empty string")
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")

    raw_records = _retrieved_records(retriever, message.strip(), limit)
    decoded_records = _decode_records(raw_records)
    context = json.dumps(decoded_records, indent=2, ensure_ascii=True, default=str)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history or [])
    messages.append({
        "role": "user",
        "content": (
            "Answer only from these retrieved and decoded packet records. "
            "State when the payload is encrypted or unavailable.\\n\\n"
            f"Decoded packet records:\\n{context}\\n\\n"
            f"Question: {message.strip()}"
        ),
    })
    selected_model = _model_name(model)
    answer = _request(messages, selected_model)
    return {
        "model": selected_model,
        "question": message.strip(),
        "answer": answer,
        "packets": decoded_records,
    }
