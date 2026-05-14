from rules_farmer.attack_discovery import DiscoveredAttack, RemoteAttackDiscovery
from rules_farmer.ssh import CommandResult


class FakeSSH:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run_command(self, command):
        self.commands.append(command)
        return self.results.pop(0)


def test_discovers_attacks_from_remote_directories_with_entrypoints():
    ssh = FakeSSH(
        [
            CommandResult(stdout="xrce-dds-udp-dos\nmqtt-publisher-flood\n", stderr="", exit_code=0),
            CommandResult(
                stdout=(
                    '# Ataque "XRCE-DDS UDP DoS"\n\n'
                    "> Executa inundacao UDP contra XRCE-DDS Agent\n\n"
                    "docker run --rm iotedu-attack-xrce-dds-udp-dos:latest "
                    '"172.17.0.2" "8888"\n'
                ),
                stderr="",
                exit_code=0,
            ),
            CommandResult(
                stdout=(
                    "#!/usr/bin/env bash\n"
                    'echo "usage: entrypoint.sh <target> <port>   # env: DURATION SCALE"\n'
                ),
                stderr="",
                exit_code=0,
            ),
            CommandResult(
                stdout=(
                    '# Ataque "MQTT Publisher Flood"\n\n'
                    "> Publica mensagens MQTT rapidamente\n\n"
                    "docker run --rm iotedu-attack-mqtt-publisher-flood:latest "
                    '"10.0.0.5" "1883"\n'
                ),
                stderr="",
                exit_code=0,
            ),
            CommandResult(
                stdout=(
                    "#!/usr/bin/env bash\n"
                    'echo "usage: entrypoint.sh <target> <port>"\n'
                ),
                stderr="",
                exit_code=0,
            ),
        ]
    )

    attacks = RemoteAttackDiscovery(
        ssh_client=ssh,
        attacks_root="/home/unipampa/ataques/attackers-claude",
    ).discover()

    assert attacks == [
        DiscoveredAttack(
            attack_id="xrce-dds-udp-dos",
            remote_path="/home/unipampa/ataques/attackers-claude/xrce-dds-udp-dos",
            description="Executa inundacao UDP contra XRCE-DDS Agent",
            docker_image="iotedu-attack-xrce-dds-udp-dos:latest",
            required_arguments=["target", "port"],
            readme_excerpt=(
                '# Ataque "XRCE-DDS UDP DoS"\n\n'
                "> Executa inundacao UDP contra XRCE-DDS Agent\n\n"
                "docker run --rm iotedu-attack-xrce-dds-udp-dos:latest "
                '"172.17.0.2" "8888"'
            ),
        ),
        DiscoveredAttack(
            attack_id="mqtt-publisher-flood",
            remote_path="/home/unipampa/ataques/attackers-claude/mqtt-publisher-flood",
            description="Publica mensagens MQTT rapidamente",
            docker_image="iotedu-attack-mqtt-publisher-flood:latest",
            required_arguments=["target", "port"],
            readme_excerpt=(
                '# Ataque "MQTT Publisher Flood"\n\n'
                "> Publica mensagens MQTT rapidamente\n\n"
                "docker run --rm iotedu-attack-mqtt-publisher-flood:latest "
                '"10.0.0.5" "1883"'
            ),
        ),
    ]
    assert "find /home/unipampa/ataques/attackers-claude" in ssh.commands[0]
    assert ssh.commands[1] == (
        "cat /home/unipampa/ataques/attackers-claude/xrce-dds-udp-dos/README.md"
    )
    assert ssh.commands[2] == (
        "cat /home/unipampa/ataques/attackers-claude/xrce-dds-udp-dos/entrypoint.sh"
    )
