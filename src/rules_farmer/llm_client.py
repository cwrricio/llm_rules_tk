from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Type

from pydantic import BaseModel


logger = logging.getLogger(__name__)


class LLMClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class LLMClientConfig:
    provider: str
    model: str
    temperature: float
    max_tokens: int
    api_key: str | None


class StructuredLLMClient:
    def __init__(self, config: LLMClientConfig):
        self.config = config

    def generate(
        self,
        system_prompt: str,
        payload: dict[str, Any],
        output_schema: Type[BaseModel],
    ) -> dict[str, Any]:
        logger.info(
            "LLM generation started provider=%s model=%s output_schema=%s",
            self.config.provider,
            self.config.model,
            output_schema.__name__,
        )
        if not self.config.api_key:
            logger.error("LLM generation blocked by missing API key provider=%s", self.config.provider)
            raise LLMClientError(
                f"Missing API key for provider={self.config.provider}. "
                "Set the appropriate env var (e.g. GROQ_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY / DEEPSEEK_API_KEY)."
            )

        user_prompt = _build_user_prompt(payload=payload, output_schema=output_schema)
        provider = self.config.provider.lower()

        try:
            if provider == "anthropic":
                text = _call_anthropic(
                    api_key=self.config.api_key,
                    model=self.config.model,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
            elif provider in {"openai", "groq", "deepseek"}:
                base_url = None
                if provider == "groq":
                    base_url = "https://api.groq.com/openai/v1"
                elif provider == "deepseek":
                    base_url = "https://api.deepseek.com/v1"
                text = _call_openai_compatible(
                    api_key=self.config.api_key,
                    base_url=base_url,
                    model=self.config.model,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
            else:
                raise LLMClientError(
                    f"Unsupported provider: {self.config.provider}. Expected anthropic/openai/groq/deepseek."
                )
        except LLMClientError:
            raise
        except Exception as exc:
            logger.exception(
                "LLM provider request failed provider=%s model=%s",
                self.config.provider,
                self.config.model,
            )
            raise LLMClientError(
                f"LLM request failed for provider={self.config.provider} "
                f"model={self.config.model}. Check config.yaml llm.*.provider/model "
                "and whether the API key has access to that model. "
                f"Original error: {exc}"
            ) from exc

        data = _extract_json_object(text)
        try:
            validated = output_schema.model_validate(data)
        except Exception as exc:
            logger.exception(
                "LLM output schema validation failed provider=%s model=%s output_schema=%s",
                self.config.provider,
                self.config.model,
                output_schema.__name__,
            )
            raise LLMClientError(
                f"Model output failed schema validation for {output_schema.__name__}: {exc}\n"
                f"Raw text:\n{text}"
            ) from exc
        logger.info(
            "LLM generation finished provider=%s model=%s output_schema=%s",
            self.config.provider,
            self.config.model,
            output_schema.__name__,
        )
        return validated.model_dump()


def _build_user_prompt(payload: dict[str, Any], output_schema: Type[BaseModel]) -> str:
    schema = output_schema.model_json_schema()
    return (
        "Return ONLY a single JSON object that matches the provided JSON schema. "
        "Do not include markdown, code fences, or extra keys.\n\n"
        f"JSON schema:\n{json.dumps(schema, ensure_ascii=False)}\n\n"
        f"Input payload:\n{json.dumps(payload, ensure_ascii=False)}\n"
    )


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()

    # Prefer a fenced json block if present.
    fenced = re.search(r"```json\s*(\{.*?\})\s*```", cleaned, re.DOTALL | re.IGNORECASE)
    if fenced:
        cleaned = fenced.group(1).strip()

    # Find first {...} block.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMClientError(f"Could not find JSON object in model output:\n{cleaned}")

    candidate = cleaned[start : end + 1]
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise LLMClientError(f"Invalid JSON from model: {exc}\nRaw:\n{candidate}") from exc

    if not isinstance(data, dict):
        raise LLMClientError(f"Expected JSON object, got {type(data).__name__}")
    return data


def _call_anthropic(
    *,
    api_key: str,
    model: str,
    temperature: float,
    max_tokens: int,
    system_prompt: str,
    user_prompt: str,
) -> str:
    from anthropic import Anthropic

    client = Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    parts = []
    for part in message.content:
        # anthropic returns TextBlock-like items
        text = getattr(part, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts).strip()


def _call_openai_compatible(
    *,
    api_key: str,
    base_url: str | None,
    model: str,
    temperature: float,
    max_tokens: int,
    system_prompt: str,
    user_prompt: str,
) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=api_key, base_url=base_url)
    completion = client.chat.completions.create(
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    return (completion.choices[0].message.content or "").strip()
