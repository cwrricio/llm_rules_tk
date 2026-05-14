from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass

from rules_farmer.ssh import SSHClient


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveredAttack:
    attack_id: str
    remote_path: str
    description: str
    docker_image: str
    required_arguments: list[str]
    readme_excerpt: str


class RemoteAttackDiscovery:
    def __init__(self, ssh_client: SSHClient, attacks_root: str):
        self.ssh_client = ssh_client
        self.attacks_root = attacks_root.rstrip("/")

    def discover(self) -> list[DiscoveredAttack]:
        logger.info("Attack discovery started attacks_root=%s", self.attacks_root)
        result = self.ssh_client.run_command(
            "find "
            f"{shlex.quote(self.attacks_root)} "
            "-mindepth 1 -maxdepth 1 -type d "
            "-exec sh -c 'for d do [ -f \"$d/entrypoint.sh\" ] && basename \"$d\"; done' sh {} +"
        )
        if result.exit_code != 0:
            logger.error(
                "Attack discovery failed attacks_root=%s error=%s",
                self.attacks_root,
                (result.stderr or result.stdout).strip(),
            )
            raise RuntimeError(
                f"Unable to discover attacks under {self.attacks_root}: "
                f"{(result.stderr or result.stdout).strip()}"
            )

        attack_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.info("Attack directories found count=%s", len(attack_ids))
        logger.debug("Attack directories found attack_ids=%s", attack_ids)
        attacks = [self._load_attack(attack_id) for attack_id in attack_ids]
        logger.info("Attack discovery finished count=%s", len(attacks))
        return attacks

    def _load_attack(self, attack_id: str) -> DiscoveredAttack:
        remote_path = f"{self.attacks_root}/{attack_id}"
        logger.debug("Loading discovered attack attack_id=%s remote_path=%s", attack_id, remote_path)
        readme = self._read_remote_file(f"{remote_path}/README.md")
        entrypoint = self._read_remote_file(f"{remote_path}/entrypoint.sh")
        attack = DiscoveredAttack(
            attack_id=attack_id,
            remote_path=remote_path,
            description=_extract_description(readme, attack_id),
            docker_image=_extract_docker_image(readme, attack_id),
            required_arguments=_extract_required_arguments(entrypoint, readme),
            readme_excerpt=_excerpt(readme),
        )
        logger.debug(
            "Loaded discovered attack attack_id=%s image=%s required_arguments=%s",
            attack.attack_id,
            attack.docker_image,
            attack.required_arguments,
        )
        return attack

    def _read_remote_file(self, remote_path: str) -> str:
        result = self.ssh_client.run_command(f"cat {shlex.quote(remote_path)}")
        if result.exit_code != 0:
            logger.warning("Remote file unavailable remote_path=%s", remote_path)
            return ""
        logger.debug("Remote file loaded remote_path=%s bytes=%s", remote_path, len(result.stdout.encode()))
        return result.stdout.strip()


def _extract_description(readme: str, attack_id: str) -> str:
    for line in readme.splitlines():
        stripped = line.strip()
        if stripped.startswith(">"):
            return stripped.removeprefix(">").strip()

    for line in readme.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()

    return attack_id.replace("-", " ")


def _extract_docker_image(readme: str, attack_id: str) -> str:
    for line in readme.splitlines():
        if "docker run" not in line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        for token in tokens:
            if token.endswith(":latest") and not token.startswith("-"):
                return token
    return f"iotedu-attack-{attack_id}:latest"


def _extract_required_arguments(entrypoint: str, readme: str) -> list[str]:
    usage_match = re.search(r"usage:\s*entrypoint\.sh\s+([^\n#]+)", entrypoint)
    if usage_match:
        return re.findall(r"<([^>]+)>", usage_match.group(1))

    docker_args = _extract_docker_example_args(readme)
    if docker_args:
        return [f"arg{index}" for index in range(1, len(docker_args) + 1)]

    return []


def _extract_docker_example_args(readme: str) -> list[str]:
    for line in readme.splitlines():
        if "docker run" not in line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue

        image_index = next(
            (index for index, token in enumerate(tokens) if token.endswith(":latest")),
            None,
        )
        if image_index is not None:
            return tokens[image_index + 1 :]
    return []


def _excerpt(text: str, max_chars: int = 1200) -> str:
    stripped = text.strip()
    if len(stripped) <= max_chars:
        return stripped
    return stripped[: max_chars - 3].rstrip() + "..."
