import pytest

from src.flow.tcp_state import next_state

HS, EST, CLOSING, CLOSED, RESET = "HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET"


def run(packets, ctx=None):
    """packets: list of (flags, direction). The first one is flagged as first packet."""
    ctx = {} if ctx is None else ctx
    states, cur = [], HS            # HS is only the placeholder the tracker stores at creation time
    for i, (flags, direction) in enumerate(packets):
        cur = next_state(cur, flags, direction, ctx, is_first_packet=(i == 0))
        states.append(cur)
    return states, ctx


def test_normal_handshake_then_data():
    s, c = run([(["SYN"], "forward"), (["SYN", "ACK"], "backward"), (["ACK"], "forward"),
                (["PSH", "ACK"], "forward"), (["ACK"], "backward")])
    assert s == [HS, HS, EST, EST, EST] and not c.get("midstream")


def test_syn_retransmit_keeps_handshake_without_synack():
    s, c = run([(["SYN"], "forward"), (["SYN"], "forward")])
    assert s == [HS, HS] and not c.get("synack_seen")


def test_closed_port_syn_then_rst_ack_is_reset():
    assert run([(["SYN"], "forward"), (["RST", "ACK"], "backward")])[0] == [HS, RESET]


def test_half_open_scan_is_reset_not_established():
    assert run([(["SYN"], "forward"), (["SYN", "ACK"], "backward"), (["RST"], "forward")])[0] == [HS, HS, RESET]


def test_filtered_port_stays_in_handshake():
    assert run([(["SYN"], "forward")])[0] == [HS]


def test_normal_close_both_fins_is_closed():
    s, _ = run([(["ACK"], "forward"), (["FIN", "ACK"], "forward"), (["ACK"], "backward"),
                (["FIN", "ACK"], "backward"), (["ACK"], "forward")])
    assert s == [EST, CLOSING, CLOSING, CLOSED, CLOSED]


def test_close_requires_final_ack_waits_for_the_ack_after_the_second_fin():
    s, _ = run([(["ACK"], "forward"), (["FIN", "ACK"], "forward"), (["ACK"], "backward"),
                (["FIN", "ACK"], "backward"), (["ACK"], "forward")],
               ctx={"tcp_close_requires_final_ack": True})
    assert s == [EST, CLOSING, CLOSING, CLOSING, CLOSED]


def test_half_close_stays_closing():
    assert run([(["ACK"], "forward"), (["FIN", "ACK"], "forward"), (["ACK"], "backward")])[0] == [EST, CLOSING, CLOSING]


def test_repeated_fin_from_the_same_side_does_not_close():
    assert run([(["ACK"], "forward"), (["FIN"], "forward"), (["FIN"], "forward")])[0] == [EST, CLOSING, CLOSING]


@pytest.mark.parametrize("terminal", [CLOSED, RESET])
@pytest.mark.parametrize("flags", [["SYN"], ["ACK"], ["FIN"], ["RST"], []])
def test_terminal_states_never_change(terminal, flags):
    assert next_state(terminal, flags, "forward", {}) == terminal


@pytest.mark.parametrize("state", [HS, EST, CLOSING])
def test_rst_wins_from_any_live_state(state):
    assert next_state(state, ["RST", "ACK"], "backward", {}) == RESET


@pytest.mark.parametrize("flags,expected,midstream,synack", [
    (["SYN"], HS, False, False),
    (["SYN", "ACK"], HS, True, True),
    (["RST"], RESET, False, False),
    (["FIN", "ACK"], CLOSING, True, False),
    (["ACK"], EST, True, False),
    (["PSH", "ACK"], EST, True, False),
    ([], EST, True, False),
])
def test_first_packet_rules(flags, expected, midstream, synack):
    ctx = {}
    assert next_state(HS, flags, "forward", ctx, is_first_packet=True) == expected
    assert bool(ctx.get("midstream")) is midstream and bool(ctx.get("synack_seen")) is synack


def test_capture_starting_at_syn_ack_completes_handshake_with_the_clients_ack():
    # First packet seen is the server's SYN/ACK (endpoint_a = server), so the client's ACK is "backward".
    s, c = run([(["SYN", "ACK"], "forward"), (["ACK"], "backward")])
    assert s == [HS, EST] and c["midstream"] is True


@pytest.mark.parametrize("flags", [["SYN", "FIN"], ["FIN", "PSH", "URG"], [], None, ["BOGUS"]])
@pytest.mark.parametrize("direction", ["forward", "backward", None])
def test_weird_input_never_raises(flags, direction):
    for state in (HS, EST, CLOSING, CLOSED, RESET):
        assert next_state(state, flags, direction, {}) in {HS, EST, CLOSING, CLOSED, RESET}


def test_flag_names_are_case_insensitive_and_strings_are_not_substring_matched():
    assert run([(["syn"], "forward"), (["syn", "ack"], "backward"), (["ack"], "forward")])[0] == [HS, HS, EST]
    assert next_state(EST, "SYN-ACK-RST", "forward", {}) == EST      # a str is not a flag list