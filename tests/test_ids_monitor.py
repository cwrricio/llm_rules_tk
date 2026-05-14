from rules_farmer.ids_monitor import IDSMonitor
from rules_farmer.ssh import CommandResult


class FakeSSH:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []

    def run_command(self, command):
        self.commands.append(command)
        return self.results.pop(0)


def test_check_fired_reads_alert_log_each_time_and_matches_sid():
    ssh = FakeSSH(
        [
            CommandResult(stdout='[**] [1:9000001:1] "alert" [**]', stderr="", exit_code=0),
            CommandResult(stdout='[**] [1:9000002:1] "other" [**]', stderr="", exit_code=0),
        ]
    )
    monitor = IDSMonitor(ssh_client=ssh, alert_log_path="/var/log/snort/alert")

    assert monitor.check_fired(9000001) is True
    assert monitor.check_fired(9000001) is False
    assert ssh.commands == [
        "cat /var/log/snort/alert",
        "cat /var/log/snort/alert",
    ]


def test_check_fired_returns_false_when_log_is_missing_or_empty():
    ssh = FakeSSH(
        [
            CommandResult(stdout="", stderr="No such file", exit_code=1),
            CommandResult(stdout="", stderr="", exit_code=0),
        ]
    )
    monitor = IDSMonitor(ssh_client=ssh, alert_log_path="/custom/alert.log")

    assert monitor.check_fired(9000001) is False
    assert monitor.check_fired(9000001) is False
