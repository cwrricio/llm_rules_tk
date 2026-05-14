import json

import pytest

from rules_farmer.errors import SIDCounterCorruptedError
from rules_farmer.sid_manager import SIDManager


def test_assign_sid_increments_counter_and_persists_mapping(tmp_path):
    counter_path = tmp_path / "sid_counter.json"
    mapping_path = tmp_path / "sid_mappings.json"
    counter_path.write_text('{"counter": 9000000}')

    manager = SIDManager(counter_path=counter_path, mapping_path=mapping_path)
    sid = manager.assign_sid("Detect MQTT brute force attempts")

    assert sid == 9000001
    assert json.loads(counter_path.read_text()) == {"counter": 9000001}
    assert json.loads(mapping_path.read_text()) == {
        "9000001": "Detect MQTT brute force attempts"
    }


@pytest.mark.parametrize("counter_contents", [None, "not-json"])
def test_missing_or_corrupted_counter_raises_recovery_error(
    tmp_path, counter_contents
):
    counter_path = tmp_path / "sid_counter.json"
    mapping_path = tmp_path / "sid_mappings.json"
    if counter_contents is not None:
        counter_path.write_text(counter_contents)

    with pytest.raises(SIDCounterCorruptedError) as error:
        SIDManager(counter_path=counter_path, mapping_path=mapping_path)

    assert str(error.value) == (
        'sid_counter.json missing or corrupted. To reset safely, delete '
        'rules_farmer_ai.rules and recreate sid_counter.json with {"counter": 9000000}.'
    )


def test_assign_sids_replaces_llm_sids_with_unique_system_sids(tmp_path):
    counter_path = tmp_path / "sid_counter.json"
    mapping_path = tmp_path / "sid_mappings.json"
    counter_path.write_text('{"counter": 9000000}')
    manager = SIDManager(counter_path=counter_path, mapping_path=mapping_path)

    assigned = manager.assign_sids(
        intent="Detect suspicious XRCE-DDS traffic",
        rules=[
            'alert udp any any -> any 7400 (msg:"a"; sid:0; rev:1;)',
            'alert udp any any -> any 7401 (msg:"b"; sid:1234567; rev:1;)',
        ],
    )

    assert [item.sid for item in assigned] == [9000001, 9000002]
    assert "sid:9000001;" in assigned[0].rule
    assert "sid:9000002;" in assigned[1].rule
    assert "sid:1234567;" not in assigned[1].rule
