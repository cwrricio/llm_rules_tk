"""Pre-process the operator intent to resolve fixed attack destinations.

The Rules Farmer testbed runs target services at fixed addresses per protocol family:
- MQTT broker → 172.17.0.2:1883 (configured via attack_destinations.mqtt)
- XRCE-DDS Agent → 172.17.0.2:8888 (configured via attack_destinations.xrce)

This module inspects the operator intent text and resolves which family applies, returning the
configured IP/port. The Orchestrator then injects this as a hard constraint into both agents:
"NEVER mutate these values; if the attack accepts port as a positional argument, use the
configured port".
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from rules_farmer.config import AttackDestinationsConfig


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FixedDestination:
    family: str
    ip: str
    port: int


# Family keywords matched case-insensitively in the operator intent.
_MQTT_PATTERN = re.compile(r"\bmqtt\b", re.IGNORECASE)
_XRCE_PATTERN = re.compile(r"\b(xrce|micro\s*xrce|dds|rtps)\b", re.IGNORECASE)


def resolve_fixed_destination(
    intent: str, destinations: AttackDestinationsConfig
) -> FixedDestination | None:
    """Detect the attack family from the operator intent and return the fixed destination.

    Returns None when no known family keyword appears in the intent. In that case the
    Orchestrator should still run, but the agents fall back to inferring the destination from
    the intent text (less safe).
    """
    if _MQTT_PATTERN.search(intent):
        logger.info("Intent preprocessing matched MQTT family intent=%r", intent)
        return FixedDestination(
            family="mqtt", ip=destinations.mqtt.ip, port=destinations.mqtt.port
        )
    if _XRCE_PATTERN.search(intent):
        logger.info("Intent preprocessing matched XRCE family intent=%r", intent)
        return FixedDestination(
            family="xrce", ip=destinations.xrce.ip, port=destinations.xrce.port
        )
    logger.warning("Intent preprocessing did not match a known family intent=%r", intent)
    return None
