import pytest

from rules_farmer.llm_client import LLMClientConfig, LLMClientError, StructuredLLMClient
from rules_farmer.schemas import RuleAgentOutput


def test_openai_compatible_provider_errors_are_actionable(monkeypatch):
    def fail_request(**kwargs):
        raise RuntimeError("model_not_found")

    monkeypatch.setattr("rules_farmer.llm_client._call_openai_compatible", fail_request)

    client = StructuredLLMClient(
        LLMClientConfig(
            provider="groq",
            model="gpt-oss-120b",
            temperature=0,
            max_tokens=2048,
            api_key="test-key",
        )
    )

    with pytest.raises(LLMClientError) as error:
        client.generate(
            system_prompt="system",
            payload={"intent": "Detect XRCE"},
            output_schema=RuleAgentOutput,
        )

    assert "provider=groq" in str(error.value)
    assert "model=gpt-oss-120b" in str(error.value)
    assert "Check config.yaml llm.*.provider/model" in str(error.value)


def test_deepseek_provider_is_openai_compatible(monkeypatch):
    def fail_request(**kwargs):
        raise RuntimeError("model_not_found")

    monkeypatch.setattr("rules_farmer.llm_client._call_openai_compatible", fail_request)

    client = StructuredLLMClient(
        LLMClientConfig(
            provider="deepseek",
            model="deepseek-v4-pro",
            temperature=0,
            max_tokens=2048,
            api_key="test-key",
        )
    )

    with pytest.raises(LLMClientError) as error:
        client.generate(
            system_prompt="system",
            payload={"intent": "Detect XRCE"},
            output_schema=RuleAgentOutput,
        )

    assert "provider=deepseek" in str(error.value)
    assert "model=deepseek-v4-pro" in str(error.value)
    assert "Check config.yaml llm.*.provider/model" in str(error.value)
