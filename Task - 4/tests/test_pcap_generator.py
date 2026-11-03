import struct

from tools.create_test_pcap import create_test_pcap


def test_creates_ethernet_pcap_with_expected_packet_count(tmp_path):
    output = tmp_path / "test-traffic.pcap"
    count = create_test_pcap(output)
    raw = output.read_bytes()

    assert count == 122
    assert raw[:4] == struct.pack("<I", 0xA1B2C3D4)
    offset = 24
    packet_count = 0
    while offset < len(raw):
        seconds, micros, included, original = struct.unpack("<IIII", raw[offset:offset + 16])
        offset += 16
        assert included == original
        offset += included
        packet_count += 1

    assert offset == len(raw)
    assert packet_count == 122


def test_rejects_invalid_destination_address(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        create_test_pcap(tmp_path / "bad.pcap", "not-an-ip")
