from pathlib import Path

import pytest

from rules_farmer.errors import PCAPRetrievalError, SSHUnreachableError
from rules_farmer.ssh import CommandResult, SSHClient


class FakeStream:
    def __init__(self, content="", exit_code=0):
        self._content = content
        self.channel = self
        self._exit_code = exit_code

    def read(self):
        return self._content.encode()

    def recv_exit_status(self):
        return self._exit_code


class FakeSFTP:
    def __init__(self):
        self.transfers = []

    def get(self, remote_path, local_path):
        self.transfers.append((remote_path, local_path))
        Path(local_path).write_bytes(b"pcap")

    def close(self):
        pass


class FakeParamikoClient:
    def __init__(self):
        self.connected_with = None
        self.commands = []
        self.sftp = FakeSFTP()

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, hostname, username, key_filename, timeout):
        self.connected_with = {
            "hostname": hostname,
            "username": username,
            "key_filename": key_filename,
            "timeout": timeout,
        }

    def exec_command(self, command):
        self.commands.append(command)
        return None, FakeStream("stdout", exit_code=7), FakeStream("stderr")

    def open_sftp(self):
        return self.sftp


def test_ssh_client_runs_commands_and_gets_files(monkeypatch, tmp_path):
    fake_client = FakeParamikoClient()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rules_farmer.ssh.paramiko.SSHClient", lambda: fake_client)
    monkeypatch.setattr("rules_farmer.ssh.paramiko.AutoAddPolicy", object)

    client = SSHClient(
        host="192.168.1.2",
        user="admin",
        key_path="~/.ssh/ids_key",
        connect_timeout=10,
    )

    result = client.run_command("docker ps")
    local_path = tmp_path / "attack.pcap"
    client.get_file("/tmp/attack.pcap", local_path)

    assert fake_client.connected_with == {
        "hostname": "192.168.1.2",
        "username": "admin",
        "key_filename": str(tmp_path / ".ssh" / "ids_key"),
        "timeout": 10,
    }
    assert result == CommandResult(stdout="stdout", stderr="stderr", exit_code=7)
    assert fake_client.commands == ["docker ps"]
    assert fake_client.sftp.transfers == [("/tmp/attack.pcap", str(local_path))]
    assert local_path.read_bytes() == b"pcap"


def test_ssh_client_retries_connection_failures_before_structured_error(monkeypatch):
    attempts = []
    sleeps = []

    class FailingParamikoClient:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, hostname, username, key_filename, timeout):
            attempts.append((hostname, username, key_filename, timeout))
            raise OSError("network unreachable")

    monkeypatch.setattr("rules_farmer.ssh.paramiko.SSHClient", FailingParamikoClient)
    monkeypatch.setattr("rules_farmer.ssh.paramiko.AutoAddPolicy", object)
    monkeypatch.setattr("rules_farmer.ssh.time.sleep", sleeps.append)

    with pytest.raises(SSHUnreachableError) as error:
        SSHClient(
            host="192.168.1.3",
            user="admin",
            key_path="~/.ssh/attacker_key",
            connect_timeout=10,
            max_attempts=3,
            base_delay_seconds=1,
        )

    assert "Unable to connect to 192.168.1.3 over SSH after 3 attempts" in str(
        error.value
    )
    assert len(attempts) == 3
    assert sleeps == [1, 2]


def test_get_file_raises_pcap_retrieval_error_when_remote_file_is_missing(
    monkeypatch, tmp_path
):
    class MissingFileSFTP(FakeSFTP):
        def get(self, remote_path, local_path):
            raise FileNotFoundError(remote_path)

    fake_client = FakeParamikoClient()
    fake_client.sftp = MissingFileSFTP()
    monkeypatch.setattr("rules_farmer.ssh.paramiko.SSHClient", lambda: fake_client)
    monkeypatch.setattr("rules_farmer.ssh.paramiko.AutoAddPolicy", object)
    client = SSHClient(
        host="192.168.1.3",
        user="admin",
        key_path="~/.ssh/attacker_key",
        connect_timeout=10,
    )

    with pytest.raises(PCAPRetrievalError):
        client.get_file("/tmp/attack.pcap", tmp_path / "attack.pcap")
