import pytest

from rules_farmer.errors import IDSReloadError
from rules_farmer.ids_rule_injector import IDSRuleInjector
from rules_farmer.ssh import CommandResult


class FakeSSH:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run_command(self, command):
        self.commands.append(command)
        return self.results.pop(0)


def test_injector_overwrites_rules_restarts_container_and_polls_until_running(
    monkeypatch,
):
    ssh = FakeSSH(
        [
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="snort_ids", stderr="", exit_code=0),
            CommandResult(stdout="false", stderr="", exit_code=0),
            CommandResult(stdout="true", stderr="", exit_code=0),
        ]
    )
    sleeps = []
    monkeypatch.setattr("rules_farmer.ids_rule_injector.time.sleep", sleeps.append)
    injector = IDSRuleInjector(
        ssh_client=ssh,
        rules_file_path="/home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/temp/rules_farmer_ai.rules",
        include_file_path="/home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules",
        include_statement="include rules/temp/rules_farmer_ai.rules",
        container_name="snort_ids",
        poll_interval_seconds=1,
    )

    injector.inject(["alert udp any any -> any any (msg:\"one\"; sid:9000001; rev:1;)"])

    assert "rules/temp/rules_farmer_ai.rules" in ssh.commands[0]
    assert "sid:9000001;" in ssh.commands[0]
    assert ssh.commands[1] == (
        "grep -Fxq 'include rules/temp/rules_farmer_ai.rules' "
        "/home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules "
        "|| printf '\\n%s\\n' 'include rules/temp/rules_farmer_ai.rules' "
        ">> /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules"
    )
    assert ssh.commands[2] == "docker restart snort_ids"
    assert ssh.commands[3:] == [
        "docker inspect -f '{{.State.Running}}' snort_ids",
        "docker inspect -f '{{.State.Running}}' snort_ids",
    ]
    assert sleeps == [1]


def test_injector_raises_reload_error_with_container_logs_when_snort_fails():
    ssh = FakeSSH(
        [
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="snort_ids", stderr="", exit_code=0),
            CommandResult(stdout="false", stderr="", exit_code=0),
            CommandResult(stdout="invalid rule", stderr="", exit_code=0),
        ]
    )
    injector = IDSRuleInjector(
        ssh_client=ssh,
        rules_file_path="/home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/temp/rules_farmer_ai.rules",
        include_file_path="/home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules",
        include_statement="include rules/temp/rules_farmer_ai.rules",
        container_name="snort_ids",
        max_health_polls=1,
    )

    with pytest.raises(IDSReloadError) as error:
        injector.inject(["alert udp any any -> any any (msg:\"bad\"; sid:9000001; rev:1;)"])

    assert "invalid rule" in str(error.value)
    assert ssh.commands[-1] == "docker logs snort_ids"


def test_clear_rules_overwrites_rules_file_with_empty_content():
    ssh = FakeSSH([CommandResult(stdout="", stderr="", exit_code=0)])
    injector = IDSRuleInjector(
        ssh_client=ssh,
        rules_file_path="/home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/temp/rules_farmer_ai.rules",
        include_file_path="/home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/all.rules",
        include_statement="include rules/temp/rules_farmer_ai.rules",
        container_name="snort_ids",
    )

    injector.clear_rules()

    assert ssh.commands == [
        "cat > /home/gtiotedu/ataques-regras-e-assinaturas/snort/rules/temp/rules_farmer_ai.rules <<'EOF'\n\nEOF"
    ]
