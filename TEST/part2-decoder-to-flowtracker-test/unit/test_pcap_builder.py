import pytest
from scapy.utils import PcapReader

from pcap_builder import tcp_packet, udp_packet, write_pcap

BASE = 1700000000.0


def _roundtrip(tmp_path, pkts):
    path = write_pcap(pkts, tmp_path / "x.pcap")
    return list(PcapReader(path))


def test_handshake_flags_and_timestamps(tmp_path):
    pkts = [
        tcp_packet("192.168.1.100", 12345, "8.8.8.8", 80, "S", ts=BASE, seq=100),
        tcp_packet("8.8.8.8", 80, "192.168.1.100", 12345, "SA", ts=BASE + 0.01, seq=300, ack=101),
        tcp_packet("192.168.1.100", 12345, "8.8.8.8", 80, "A", ts=BASE + 0.02, seq=101, ack=301),
    ]
    got = _roundtrip(tmp_path, pkts)
    assert [str(p["TCP"].flags) for p in got] == ["S", "SA", "A"]
    for p, exp in zip(got, [BASE, BASE + 0.01, BASE + 0.02]):
        assert float(p.time) == pytest.approx(exp, abs=1e-6)


def test_mac_symmetric_and_deterministic():
    fwd = tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, "S", ts=BASE)
    bwd = tcp_packet("10.0.0.2", 2, "10.0.0.1", 1, "SA", ts=BASE + 0.01)
    assert fwd.src == bwd.dst and fwd.dst == bwd.src
    assert bytes(fwd) == bytes(tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, "S", ts=BASE))


def test_ts_is_required():
    with pytest.raises(TypeError):
        tcp_packet("10.0.0.1", 1, "10.0.0.2", 2, "S")


def test_udp_length(tmp_path):
    got = _roundtrip(tmp_path, [udp_packet("10.0.0.1", 5000, "10.0.0.2", 53, ts=BASE, payload=b"abc")])
    assert got[0]["UDP"].len == 11