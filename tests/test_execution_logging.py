from io import StringIO

from rules_farmer.execution_logging import configure_execution_logging, format_stage, log_stage


def test_format_stage_builds_visible_divider():
    assert (
        format_stage("agora esta rodando o atacante")
        == "<------------- AGORA ESTA RODANDO O ATACANTE ------------->"
    )


def test_stage_logging_writes_divider_to_terminal_and_file(tmp_path):
    stream = StringIO()
    log_path = tmp_path / "output.log"

    configure_execution_logging(log_path=log_path, stream=stream)
    log_stage("agora esta rodando o atacante")

    terminal_text = stream.getvalue()
    file_text = log_path.read_text(encoding="utf-8")

    assert "<------------- AGORA ESTA RODANDO O ATACANTE ------------->" in terminal_text
    assert "<------------- AGORA ESTA RODANDO O ATACANTE ------------->" in file_text
