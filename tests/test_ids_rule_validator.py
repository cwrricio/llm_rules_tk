from rules_farmer.ids_rule_validator import SnortRuleValidator, ValidationResult
from rules_farmer.ssh import CommandResult


class FakeSSH:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run_command(self, command):
        self.commands.append(command)
        return self.results.pop(0)


def test_validator_writes_candidate_rule_and_returns_valid_result():
    ssh = FakeSSH(
        [
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="Snort successfully validated", stderr="", exit_code=0),
        ]
    )
    validator = SnortRuleValidator(
        ssh_client=ssh,
        temp_rule_path="/tmp/rules_farmer_candidate.rules",
    )

    result = validator.validate('alert udp any any -> any any (msg:"ok"; sid:0; rev:1;)')

    assert result == ValidationResult(valid=True, error=None)
    assert "rules_farmer_candidate.rules" in ssh.commands[0]
    assert 'sid:0;' in ssh.commands[0]
    assert ssh.commands[1] == (
        "docker cp /tmp/rules_farmer_candidate.rules "
        "snort_ids:/tmp/rules_farmer_candidate.rules"
    )
    assert ssh.commands[2] == (
        "docker exec snort_ids snort -c /opt/snort3/etc/snort/snort.lua "
        "-R /tmp/rules_farmer_candidate.rules -T"
    )


def test_validator_returns_stderr_when_snort_rejects_rule():
    ssh = FakeSSH(
        [
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="", stderr="", exit_code=0),
            CommandResult(stdout="", stderr="unknown rule option", exit_code=1),
        ]
    )
    validator = SnortRuleValidator(ssh_client=ssh)

    result = validator.validate('alert udp any any -> any any (msg:"bad"; sid:0; rev:1;)')

    assert result == ValidationResult(valid=False, error="unknown rule option")
