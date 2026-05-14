from pathlib import Path

from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.attack_executor import (
    AttackExecutor,
    ExecutionResult,
)
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


def test_attack_executor_runs_discovered_docker_attack_with_temp_pcap_and_retrieves_pcap(
    tmp_path,
):
    ssh = FakeSSH(
        [
            CommandResult(stdout="/tmp/rules-farmer-attack-a1b2c3\n", stderr="", exit_code=0),
            CommandResult(
                stdout=(
                    '{"pcap_path": "/tmp/rules-farmer-attack-a1b2c3/attack.pcap",'
                    ' "exit_code": 0,'
                    ' "stdout_path": "/tmp/rules-farmer-attack-a1b2c3/stdout.txt",'
                    ' "stderr_path": "/tmp/rules-farmer-attack-a1b2c3/stderr.txt"}'
                ),
                stderr="",
                exit_code=0,
            ),
            CommandResult(stdout="", stderr="", exit_code=0),  # cat stderr_path
        ]
    )
    executor = AttackExecutor(
        ssh_client=ssh,
        attacks={
            "mqtt-bruteforce": DiscoveredAttack(
                attack_id="mqtt-bruteforce",
                remote_path="/home/unipampa/ataques/attackers-claude/mqtt-bruteforce",
                description="MQTT credential brute force",
                docker_image="iotedu-attack-mqtt-bruteforce:latest",
                required_arguments=["target", "port", "username"],
                readme_excerpt="MQTT credential brute force",
            )
        },
        pcap_output_dir=tmp_path / "pcaps",
        capture_interface="any",
        pcap_summarizer=lambda path: f"summary for {path.name}",
    )

    result = executor.execute(
        "mqtt-bruteforce",
        ["10.0.0.5", "1883", "admin"],
    )

    expected_pcap = tmp_path / "pcaps" / "mqtt-bruteforce-rules-farmer-attack-a1b2c3.pcap"
    assert ssh.commands[0] == "mktemp -d /tmp/rules-farmer-attack-XXXXXX"
    assert "tcpdump -i any" in ssh.commands[1]
    assert "docker run --rm --name rules-farmer-mqtt-bruteforce-" in ssh.commands[1]
    assert "iotedu-attack-mqtt-bruteforce:latest 10.0.0.5 1883 admin" in ssh.commands[1]
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
