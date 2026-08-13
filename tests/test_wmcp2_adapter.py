from pathlib import Path

from immune_gateway.adapters import WMCP2GatewayAdapter

ROOT = Path(__file__).resolve().parents[1]


def test_wmcp2_adapter_is_gateway_owned():
    adapter = WMCP2GatewayAdapter()
    assert adapter.system_id == "wmcp2"
    assert adapter.adapter_id == "wmcp2-local"


def test_legacy_core_module_has_no_transport_implementation():
    text = (ROOT / "immune_core" / "wmcp2_adapter.py").read_text(encoding="utf-8")
    assert "socket" not in text
    assert "urllib" not in text
    assert "WMCP2ReadOnlySensor" not in text
