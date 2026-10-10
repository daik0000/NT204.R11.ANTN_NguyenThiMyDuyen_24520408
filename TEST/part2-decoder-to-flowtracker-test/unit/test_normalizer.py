import copy

from src.models.event import IDSEvent
from src.preprocessor.normalizer import normalize, normalize_domain, normalize_host, normalize_uri_path


def test_domain_is_stripped_lowercased_and_loses_exactly_one_trailing_dot():
    assert normalize_domain("  WwW.ExAmPlE.CoM. ") == "www.example.com"
    assert normalize_domain("example.com..") == "example.com."


def test_host_keeps_the_port_and_handles_ipv6_brackets():
    assert normalize_host("Example.COM:8080") == "example.com:8080"
    assert normalize_host("EXAMPLE.com.:8080") == "example.com:8080"
    assert normalize_host("[2001:DB8::1]:8080") == "[2001:db8::1]:8080"
    assert normalize_host("Example.COM") == "example.com"
    assert normalize_host("") == ""


def test_uri_path_uppercases_hex_and_keeps_traversal_evidence():
    assert normalize_uri_path("/a%2fb%3a") == "/a%2Fb%3A"
    assert normalize_uri_path("//a/../b/./c") == "//a/../b/./c"          # no collapsing, no resolving


def test_uri_path_leading_slash_and_special_forms():
    assert normalize_uri_path("") == "/"
    assert normalize_uri_path("index.html") == "/index.html"
    assert normalize_uri_path("*") == "*"
    for absolute in ("http://a.com/x", "HTTP://A.com/x", "https://a.com/"):
        assert normalize_uri_path(absolute) == absolute


def test_timestamp_int_becomes_float_and_iso_is_derived_in_utc():
    ev = IDSEvent(1, 1700000000)
    assert "timestamp" in normalize(ev, {})
    assert ev.timestamp == 1700000000.0 and isinstance(ev.timestamp, float)
    assert ev.timestamp_iso == "2023-11-14T22:13:20+00:00"


def test_already_canonical_event_reports_no_change():
    ev = IDSEvent(1, 1700000000.0, network_protocol="IPv4", transport_protocol="TCP", src_ip="1.2.3.4")
    assert normalize(ev, {}) == [] and ev.timestamp_iso is not None


def test_protocol_aliases_are_canonicalized_and_unknown_names_untouched():
    ev = IDSEvent(1, 1.0, network_protocol="ip", transport_protocol="tcp", app_protocol="Http")
    assert normalize(ev, {}) == ["app_protocol", "network_protocol", "transport_protocol"]
    assert (ev.network_protocol, ev.transport_protocol, ev.app_protocol) == ("IPv4", "TCP", "HTTP")
    odd = IDSEvent(1, 1.0, transport_protocol="SCTP")
    normalize(odd, {})
    assert odd.transport_protocol == "SCTP"


def test_ip_addresses_are_canonicalized():
    ev = IDSEvent(1, 1.0, src_ip="2001:DB8:0:0:0:0:0:1", dst_ip=" 10.0.0.2 ")
    changes = normalize(ev, {})
    assert (ev.src_ip, ev.dst_ip) == ("2001:db8::1", "10.0.0.2") and {"src_ip", "dst_ip"} <= set(changes)


def test_invalid_ip_is_recorded_as_reason_and_left_untouched():
    ev = IDSEvent(1, 1.0, src_ip="999.1.1.1")
    normalize(ev, {})
    assert ev.src_ip == "999.1.1.1" and ev.reason == ["invalid_src_ip_format"]
    normalize(ev, {})
    assert ev.reason == ["invalid_src_ip_format"]                         # not duplicated


def _http(**app):
    return IDSEvent(1, 1.0, app_protocol="HTTP", app_fields=app)


def test_t05_header_names_values_and_host_are_normalized_without_touching_raw():
    pairs = [["HOST", " WwW.ExAmPlE.CoM:8080 "], ["CONTENT-type", "text/html"], ["User-AGENT", "x"]]
    ev = _http(headers={"HOST": "x"}, header_pairs=copy.deepcopy(pairs))
    raw = copy.deepcopy(ev.app_fields)
    assert "headers" in normalize(ev, {})
    assert ev.app_fields["headers_normalized"] == {"host": "www.example.com:8080",
                                                   "content-type": "text/html", "user-agent": "x"}
    assert ev.app_fields["headers"] == raw["headers"] and ev.app_fields["header_pairs"] == raw["header_pairs"]


def test_duplicate_headers_are_joined_but_set_cookie_stays_a_list():
    ev = _http(header_pairs=[["Accept", "a"], ["ACCEPT", "b"],
                             ["Set-Cookie", "x=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT"], ["SET-COOKIE", "y=2"]])
    normalize(ev, {})
    assert ev.app_fields["headers_normalized"]["accept"] == "a, b"
    assert ev.app_fields["headers_normalized"]["set-cookie"] == ["x=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "y=2"]


def test_malformed_header_pairs_do_not_crash():
    for bad in (None, "text", [["only-name"], [1, 2], ["ok", "v"]]):
        ev = _http(header_pairs=bad)
        normalize(ev, {})
    assert ev.app_fields["headers_normalized"] == {"ok": "v"}


def test_t05_path_normalized_comes_from_the_raw_uri_and_drops_the_query():
    ev = _http(uri="/a%2fb/../c?x=%2f", path="/a%2fb/../c?x=%2f")
    ev.decoded_fields = {"uri": {"value": "/a/b/../c?x=/"}}               # decoder output must not change the result
    assert "path" in normalize(ev, {})
    assert ev.app_fields["path_normalized"] == "/a%2Fb/../c"
    assert ev.app_fields["uri"] == "/a%2fb/../c?x=%2f"


def test_path_falls_back_to_the_path_field_and_connect_targets_are_untouched():
    ev = _http(path="p%2fq?x=1")
    normalize(ev, {})
    assert ev.app_fields["path_normalized"] == "/p%2Fq"
    connect = _http(method="CONNECT", uri="example.com:443", path="example.com:443")
    normalize(connect, {})
    assert connect.app_fields["path_normalized"] == "example.com:443"


import copy

from src.models.event import IDSEvent
from src.preprocessor.normalizer import normalize


def _http(**app):
    return IDSEvent(1, 1.0, app_protocol="HTTP", app_fields=app)


def _dns(queries=(), answers=()):
    return IDSEvent(1, 1.0, app_protocol="DNS",
                    app_fields={"queries": list(queries), "answers": list(answers)})


def test_dns_names_are_normalized_in_new_fields_and_raw_is_untouched():
    ev = _dns([{"name": "WWW.Example.COM", "qtype": "A"}],
              [{"name": "WWW.Example.COM", "type": "CNAME", "data": "CDN.Example.NET"},
               {"name": "cdn.example.net", "type": "A", "data": "93.184.216.34"},
               {"name": "x.example.com", "type": "TXT", "data": "Keep-CASE-Text"}])
    raw = copy.deepcopy(ev.app_fields)
    assert normalize(ev, {}) == ["domain"]
    assert ev.app_fields["queries"] == raw["queries"] and ev.app_fields["answers"] == raw["answers"]
    assert ev.app_fields["queries_normalized"] == [{"name": "www.example.com", "qtype": "A"}]
    answers = ev.app_fields["answers_normalized"]
    assert answers[0] == {"name": "www.example.com", "type": "CNAME", "data": "cdn.example.net"}
    assert answers[2]["data"] == "Keep-CASE-Text"                          # only domain-valued data is touched


def test_dns_event_with_lowercase_names_reports_no_change_but_still_has_the_normalized_view():
    ev = _dns([{"name": "example.com", "qtype": "A"}])
    assert normalize(ev, {}) == []
    assert ev.app_fields["queries_normalized"] == ev.app_fields["queries"]


def test_dns_malformed_elements_are_kept_untouched_and_do_not_crash():
    ev = _dns(["junk", {"qtype": "A"}, {"name": 5}])
    normalize(ev, {})
    assert ev.app_fields["queries_normalized"] == ["junk", {"qtype": "A"}, {"name": 5}]


def test_clean_http_event_reports_no_change_yet_has_normalized_views():
    ev = _http(header_pairs=[["host", "a.com"], ["accept", "x"]], uri="/x?y=1", method="GET")
    assert normalize(ev, {}) == []
    assert ev.app_fields["headers_normalized"] == {"host": "a.com", "accept": "x"}
    assert ev.app_fields["path_normalized"] == "/x"


def test_http_changes_are_reported_per_kind():
    assert normalize(_http(header_pairs=[["HOST", "a.com"]]), {}) == ["headers"]
    assert normalize(_http(header_pairs=[["accept", "a"], ["accept", "b"]]), {}) == ["headers"]   # duplicates merged
    assert normalize(_http(header_pairs=[["host", "A.com"]]), {}) == ["headers"]                  # host value lowered
    assert normalize(_http(uri="/a%2fb"), {}) == ["path"]
    assert normalize(_http(uri="index.html"), {}) == ["path"]                                      # leading slash added


def test_result_is_stable_across_repeated_calls_because_raw_is_never_overwritten():
    ev = _http(header_pairs=[["HOST", "A.com"]], uri="/x%2f", host="A.COM")
    first = normalize(ev, {})
    assert first == ["domain", "headers", "path"]
    assert normalize(ev, {}) == first


def test_connect_method_is_case_insensitive_and_keeps_the_authority_form():
    for method in ("CONNECT", "connect"):
        ev = _http(method=method, uri="example.com:443")
        normalize(ev, {})
        assert ev.app_fields["path_normalized"] == "example.com:443"


def test_host_field_is_never_overwritten():
    ev = _http(host="WwW.EX.com")
    assert normalize(ev, {}) == ["domain"]
    assert ev.app_fields["host"] == "WwW.EX.com" and ev.app_fields["host_normalized"] == "www.ex.com"