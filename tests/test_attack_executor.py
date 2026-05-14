from rules_farmer.attack_discovery import DiscoveredAttack
from rules_farmer.attack_executor import AttackExecutor, ExecutionResult
from rules_farmer.ssh import CommandResult


class FakeSSH:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run_command(self, command):
        self.commands.append(command)
        return self.results.pop(0)


_DISCOVERED_MQTT = DiscoveredAttack(
    attack_id="mqtt-bruteforce",
    remote_path="/home/unipampa/ataques/attackers-claude/mqtt-bruteforce",
    description="MQTT credential brute force",
    docker_image="iotedu-attack-mqtt-bruteforce:latest",
    required_arguments=["target", "port", "username"],
    readme_excerpt="MQTT credential brute force",
)

_ATTACK_JSON = (
    '{"exit_code": 0,'
    ' "stdout_path": "/tmp/rules-farmer-attack-a1b2c3/stdout.txt",'
    ' "stderr_path": "/tmp/rules-farmer-attack-a1b2c3/stderr.txt"}'
)


def _make_ssh():
    return FakeSSH(
        [
            CommandResult(stdout="/tmp/rules-farmer-attack-a1b2c3\n", stderr="", exit_code=0),
            CommandResult(stdout=_ATTACK_JSON, stderr="", exit_code=0),
            CommandResult(stdout="", stderr="", exit_code=0),  # cat stderr_path
        ]
    )


def test_attack_executor_runs_discovered_docker_attack_and_returns_exit_code():
    ssh = _make_ssh()
    executor = AttackExecutor(
        ssh_client=ssh,
        attacks={"mqtt-bruteforce": _DISCOVERED_MQTT},
    )

    result = executor.execute("mqtt-bruteforce", ["10.0.0.5", "1883", "admin"])

    script = ssh.commands[1]
    assert ssh.commands[0] == "mktemp -d /tmp/rules-farmer-attack-XXXXXX"
    assert "docker run -d --name iotedu-attack-mqtt-bruteforce" in script
    assert "iotedu-attack-mqtt-bruteforce:latest 10.0.0.5 1883 admin" in script
    assert "docker wait iotedu-attack-mqtt-bruteforce" in script
    assert "docker logs iotedu-attack-mqtt-bruteforce" in script
    # Capture-related commands must NOT be present.
    assert "tcpdump" not in script
    assert ".pcap" not in script
    assert result == ExecutionResult(
        exit_code=0,
        stdout_json={
            "exit_code": 0,
            "stdout_path": "/tmp/rules-farmer-attack-a1b2c3/stdout.txt",
            "stderr_path": "/tmp/rules-farmer-attack-a1b2c3/stderr.txt",
        },
        container_exit_code=0,
        container_stderr="",
    )


def test_attack_executor_returns_container_stderr_when_present():
    ssh = FakeSSH(
        [
            CommandResult(stdout="/tmp/rules-farmer-attack-a1b2c3\n", stderr="", exit_code=0),
            CommandResult(stdout=_ATTACK_JSON, stderr="", exit_code=0),
            CommandResult(stdout="connection refused", stderr="", exit_code=0),
        ]
    )
    executor = AttackExecutor(
        ssh_client=ssh,
        attacks={"mqtt-bruteforce": _DISCOVERED_MQTT},
    )

    result = executor.execute("mqtt-bruteforce", ["10.0.0.5", "1883", "admin"])

    assert result.container_stderr == "connection refused"
    assert result.container_exit_code == 0
