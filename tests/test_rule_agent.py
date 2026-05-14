from rules_farmer.rule_agent import RuleAgent
from rules_farmer.schemas import RuleAgentOutput


class FakeLLM:
    def __init__(self):
        self.calls = []

    def generate(self, system_prompt, payload, output_schema):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "payload": payload,
                "output_schema": output_schema,
            }
        )
        return {
            "rules": ['alert udp any any -> any any (msg:"Detect MQTT"; sid:0; rev:1;)'],
            "diagnosis": None,
        }


def test_rule_agent_returns_structured_output_and_prompts_for_snort_sid_zero():
    llm = FakeLLM()
    agent = RuleAgent(llm_client=llm, provider="anthropic", model="claude-sonnet-4-6")

    output = agent.run(intent="Detect MQTT")

    assert output == RuleAgentOutput(
        rules=['alert udp any any -> any any (msg:"Detect MQTT"; sid:0; rev:1;)'],
        diagnosis=None,
    )
    assert llm.calls[0]["output_schema"] is RuleAgentOutput
    assert "Snort 3.9.12.0" in llm.calls[0]["system_prompt"]
    assert "sid:0" in llm.calls[0]["system_prompt"]
    assert "msg field must contain the operator intent verbatim" in llm.calls[0][
        "system_prompt"
    ]
    assert llm.calls[0]["payload"] == {
        "intent": "Detect MQTT",
        "previous_rules": None,
        "feedback": None,
    }
