from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.attacker_agent import AttackerAgent
from rules_farmer.schemas import AttackPlan, AttackerRequest


class FakeLLM:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def generate(self, system_prompt, payload, output_schema):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "payload": payload,
                "output_schema": output_schema,
            }
        )
        return self.outputs.pop(0)


def test_attacker_agent_reuses_conversation_to_correct_invalid_argument_count():
    llm = FakeLLM(
        [
            {
                "attack_id": "mqtt-bruteforce",
                "arguments": ["10.0.0.5"],
                "evasion_rationale": "Probe non-default broker port handling",
            },
            {
                "attack_id": "mqtt-bruteforce",
                "arguments": ["10.0.0.5", "1883"],
                "evasion_rationale": "Probe non-default broker port handling",
            },
        ]
    )
    agent = AttackerAgent(
        llm_client=llm,
        attacks=[
            DiscoveredAttack(
                attack_id="mqtt-bruteforce",
                remote_path="/home/unipampa/ataques/attackers-claude/mqtt-bruteforce",
                description="MQTT credential brute force",
                docker_image="iotedu-attack-mqtt-bruteforce:latest",
                required_arguments=["target", "port"],
                readme_excerpt="Run MQTT brute force against <target> <port>.",
            )
        ],
        max_plan_retries=3,
    )

    plan = agent.run(
        AttackerRequest(
            intent="Detect MQTT brute force",
            rule='alert tcp any any -> any 1883 (msg:"Detect MQTT brute force"; sid:9000001; rev:1;)',
            sid=9000001,
            variant_history=[],
        )
    )

    assert plan == AttackPlan(
        attack_id="mqtt-bruteforce",
        arguments=["10.0.0.5", "1883"],
        evasion_rationale="Probe non-default broker port handling",
    )
    assert llm.calls[0]["output_schema"] is AttackPlan
    assert "mqtt-bruteforce" in llm.calls[0]["system_prompt"]
    assert llm.calls[1]["payload"]["correction"] == {
        "attack_id": "mqtt-bruteforce",
        "field": "arguments",
        "expected_count": "2",
        "actual_count": "1",
    }
