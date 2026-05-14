from pathlib import Path

import pytest

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.attack_executor import (
    AttackExecutor,
    ExecutionResult,
)
from rules_farmer.errors import PCAPRetrievalError
from rules_farmer.ssh import CommandResult


class FakeSSH:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []
        self.transfers = []

    def run_command(self, command):
        self.commands.append(command)
        return self.results.pop(0)

    def get_file(self, remote_path, local_path):
        self.transfers.append((remote_path, Path(local_path)))
        Path(local_path).write_bytes(b"pcap")


class PCAPMissingSSH(FakeSSH):
    def get_file(self, remote_path, local_path):
        raise PCAPRetrievalError(f"PCAP not found at {remote_path}")


_DISCOVERED_MQTT = DiscoveredAttack(
    attack_id="mqtt-bruteforce",
    remote_path="/home/unipampa/ataques/attackers-claude/mqtt-bruteforce",
    description="MQTT credential brute force",
    docker_image="iotedu-attack-mqtt-bruteforce:latest",
    required_arguments=["target", "port", "username"],
    readme_excerpt="MQTT credential brute force",
)

_ATTACK_JSON = (
    '{"pcap_path": "/tmp/rules-farmer-attack-a1b2c3/attack.pcap",'
    ' "exit_code": 0,'
    ' "stdout_path": "/tmp/rules-farmer-attack-a1b2c3/stdout.txt",'
    ' "stderr_path": "/tmp/rules-farmer-attack-a1b2c3/stderr.txt"}'
)


def _make_ssh(extra_results=None):
    results = [
        CommandResult(stdout="/tmp/rules-farmer-attack-a1b2c3\n", stderr="", exit_code=0),
        CommandResult(stdout=_ATTACK_JSON, stderr="", exit_code=0),
        CommandResult(stdout="", stderr="", exit_code=0),  # cat stderr_path
    ]
    if extra_results:
        results.extend(extra_results)
    return FakeSSH(results)


def test_attack_executor_runs_discovered_docker_attack_with_temp_pcap_and_retrieves_pcap(
    tmp_path,
):
    ssh = _make_ssh()
    executor = AttackExecutor(
        ssh_client=ssh,
        attacks={"mqtt-bruteforce": _DISCOVERED_MQTT},
        pcap_output_dir=tmp_path / "pcaps",
        capture_interface="any",
        pcap_summarizer=lambda path: f"summary for {path.name}",
    )

    result = executor.execute("mqtt-bruteforce", ["10.0.0.5", "1883", "admin"])

    expected_pcap = tmp_path / "pcaps" / "mqtt-bruteforce-rules-farmer-attack-a1b2c3.pcap"
    script = ssh.commands[1]
    assert ssh.commands[0] == "mktemp -d /tmp/rules-farmer-attack-XXXXXX"
    # Detached mode with exact image-derived container name.
    assert "docker run -d --name iotedu-attack-mqtt-bruteforce" in script
    assert "iotedu-attack-mqtt-bruteforce:latest 10.0.0.5 1883 admin" in script
    # tcpdump capture during docker wait window.
    assert "tcpdump -i any" in script
    assert "docker wait iotedu-attack-mqtt-bruteforce" in script
    # Logs collected via docker logs, not stdout redirect.
    assert "docker logs iotedu-attack-mqtt-bruteforce" in script
    assert ssh.transfers == [("/tmp/rules-farmer-attack-a1b2c3/attack.pcap", expected_pcap)]
    assert result == ExecutionResult(
        exit_code=0,
        stdout_json={
            "pcap_path": "/tmp/rules-farmer-attack-a1b2c3/attack.pcap",
            "exit_code": 0,
            "stdout_path": "/tmp/rules-farmer-attack-a1b2c3/stdout.txt",
            "stderr_path": "/tmp/rules-farmer-attack-a1b2c3/stderr.txt",
        },
        pcap_local_path=expected_pcap,
        pcap_summary="summary for mqtt-bruteforce-rules-farmer-attack-a1b2c3.pcap",
        container_exit_code=0,
        container_stderr="",
    )


def test_attack_executor_continues_without_pcap_when_capture_fails(tmp_path):
    ssh = PCAPMissingSSH(
        [
            CommandResult(stdout="/tmp/rules-farmer-attack-a1b2c3\n", stderr="", exit_code=0),
            CommandResult(stdout=_ATTACK_JSON, stderr="", exit_code=0),
            CommandResult(stdout="", stderr="", exit_code=0),
        ]
    )
    executor = AttackExecutor(
        ssh_client=ssh,
        attacks={"mqtt-bruteforce": _DISCOVERED_MQTT},
        pcap_output_dir=tmp_path / "pcaps",
        capture_interface="any",
        pcap_summarizer=lambda path: f"summary for {path.name}",
    )

    result = executor.execute("mqtt-bruteforce", ["10.0.0.5", "1883", "admin"])

    assert result.pcap_summary == ""
    assert result.container_exit_code == 0
