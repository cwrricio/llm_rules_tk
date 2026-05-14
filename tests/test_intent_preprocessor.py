"""Tests for the intent preprocessor that resolves fixed attack destinations."""

from rules_farmer.config import AttackDestination, AttackDestinationsConfig
from rules_farmer.intent_preprocessor import FixedDestination, resolve_fixed_destination


_DESTINATIONS = AttackDestinationsConfig(
    mqtt=AttackDestination(ip="172.17.0.2", port=1883),
    xrce=AttackDestination(ip="172.17.0.2", port=8888),
)


def test_resolve_fixed_destination_detects_mqtt_family():
    fixed = resolve_fixed_destination(
        "Detect MQTT brute force against the broker", _DESTINATIONS
    )
    assert fixed == FixedDestination(family="mqtt", ip="172.17.0.2", port=1883)


def test_resolve_fixed_destination_detects_xrce_family():
    fixed = resolve_fixed_destination(
        "Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888", _DESTINATIONS
    )
    assert fixed == FixedDestination(family="xrce", ip="172.17.0.2", port=8888)


def test_resolve_fixed_destination_detects_dds_keyword():
    fixed = resolve_fixed_destination(
        "Detect a DDS entity flood", _DESTINATIONS
    )
    assert fixed is not None
    assert fixed.family == "xrce"


def test_resolve_fixed_destination_detects_rtps_keyword():
    fixed = resolve_fixed_destination(
        "Block malformed RTPS DATA_FRAG flooding", _DESTINATIONS
    )
    assert fixed is not None
    assert fixed.family == "xrce"


def test_resolve_fixed_destination_returns_none_for_unknown_intent():
    fixed = resolve_fixed_destination(
        "Detect generic HTTP scanning", _DESTINATIONS
    )
    assert fixed is None


def test_resolve_fixed_destination_is_case_insensitive():
    fixed = resolve_fixed_destination("DETECT mqtt FLOOD", _DESTINATIONS)
    assert fixed is not None
    assert fixed.family == "mqtt"


def test_resolve_fixed_destination_prefers_mqtt_over_xrce_when_both_present():
    """MQTT is checked first because its keyword is more specific. This avoids ambiguity for
    intents that mention 'DDS over MQTT' or similar wording — the test pins the precedence."""
    fixed = resolve_fixed_destination(
        "Detect MQTT abuse that also uses DDS underneath", _DESTINATIONS
    )
    assert fixed is not None
    assert fixed.family == "mqtt"
