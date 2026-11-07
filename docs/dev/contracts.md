# Internal module contracts (v0.1)

Read with `docs/design/v0.1-design.md`. The shared data model is `src/bacnet_health/model.py`. Do not change its field
names without updating every consumer.

Rules for all code:

- Python ≥ 3.10, **stdlib only** outside `bacnet_health.gui` (PySide6). Type hints everywhere. Use `from __future__ import annotations`.
- Every decoder is bounds-checked and raises `bacnet_health.wire.DecodeError` (subclass of `ValueError`) on bad input.
  Never `IndexError`/`struct.error` escaping.
- English only in all user-facing text. No client, building or employer names. Use documentation IP ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or RFC 1918 in samples and tests.
- **Prohibited-service encoders (WriteProperty, DCC, ReinitializeDevice, …) must not exist under `src/`.** Tests that
  need such frames build them by hand under `tests/helpers/`.
- Tests live in `tests/`, run with `.venv/bin/pytest`. Python is `.venv/bin/python` (3.11).

## wire/ — BACnet encoding (owner: wire agent)

```
wire/__init__.py      DecodeError, re-exports
wire/constants.py     IntEnums: BvlcFunction, BvlcResult, NetworkMessage, PduType, ConfirmedService,
                      UnconfirmedService, ObjectType, PropertyId, ErrorClass, ErrorCode, RejectReason, AbortReason,
                      Segmentation, DeviceStatus; helpers name_of(enum, value) -> str ("unknown-123" fallback)
wire/tags.py          application/context tag encode+decode for: null, boolean, unsigned, signed, real, double,
                      octet-string, character-string (UTF-8, UCS-2, ISO-8859-1; others -> repr), bit-string,
                      enumerated, date, time, object-identifier; opening/closing tags; decode_any_application()
wire/bvlc.py          @dataclass Bvlc(function, length, npdu: bytes|None, origin: tuple[str,int]|None,
                      result_code: int|None, bdt: list[BdtEntry]|None, fdt: list[FdtEntry]|None, ttl: int|None)
                      decode_bvlc(data: bytes) -> Bvlc
                      encode_original_unicast(npdu), encode_original_broadcast(npdu), encode_read_bdt(),
                      encode_read_fdt(), encode_register_foreign_device(ttl), encode_distribute_broadcast(npdu)
                      # responder-side (simulator/synth only):
                      encode_result(code), encode_read_bdt_ack(entries), encode_read_fdt_ack(entries),
                      encode_forwarded_npdu(origin_ip, origin_port, npdu)
wire/npdu.py          @dataclass Npdu(control, dnet, dadr: bytes|None, snet, sadr: bytes|None, hop_count,
                      expecting_reply, priority, network_message: int|None, network_payload: bytes|None,
                      apdu: bytes|None)
                      decode_npdu(data) -> Npdu; encode_npdu(apdu, *, dnet=None, dadr=None, snet=None, sadr=None,
                      expecting_reply=False, hop_count=255)
                      encode_network_message(msg_type, payload, ...) (synth: I-Am-Router-To-Network,
                      Reject-Message-To-Network, Who-Is-Router-To-Network)
wire/apdu.py          @dataclass Apdu(pdu_type, service: int|None, invoke_id: int|None, segmented, more_follows,
                      sequence, window, max_segments, max_apdu, reason: int|None, payload: bytes)
                      decode_apdu(data) -> Apdu
                      service payload decoders: decode_who_is -> (low, high)|None; decode_i_am -> IAm;
                      decode_read_property_request -> RpRequest; decode_read_property_ack -> RpAck;
                      decode_rpm_request; decode_rpm_ack -> list[RpmResult]; decode_error -> (class, code);
                      decode_who_has, decode_i_have (summary only)
                      client encoders: encode_who_is(low=None, high=None); encode_read_property(invoke_id,
                      obj_type, instance, prop, index=None, max_apdu=1476); encode_rpm(invoke_id, obj_type,
                      instance, props: list[tuple[prop, index|None]], max_apdu=1476)
                      responder encoders (simulator/synth): encode_i_am, encode_read_property_ack,
                      encode_rpm_ack, encode_error, encode_reject, encode_abort, encode_simple_ack
wire/message.py       @dataclass BacnetMessage: bvlc, npdu, apdu, kind (str summary e.g. "who-is", "i-am",
                      "read-property", "rp-ack", "rpm", "rpm-ack", "error", "reject", "abort", "write-property",
                      "dcc", "reinitialize", "net:<name>", "bvlc:<name>", ...), service_name, decoded (service object
                      or None), decode_error: str|None
                      decode_message(udp_payload: bytes) -> BacnetMessage   # never raises; sets decode_error
                      looks_like_bacnet(payload) -> bool   # 0x81 type + valid length
wire/txguard.py       class TxBlocked(Exception); check_tx(frame: bytes) -> None
                      Allowed: BVLC Read-BDT, Read-FDT, Register-FD, Distribute-Broadcast, Original-Unicast,
                      Original-Broadcast. NPDU must not be a network message. APDU must be Unconfirmed Who-Is or
                      Confirmed ReadProperty / ReadPropertyMultiple. Everything else raises TxBlocked.
```

## capture/ — files and link layers (owner: capture agent)

```
capture/pcap.py       @dataclass RawPacket(frame_no: int (1-based), ts: float, linktype: int, data: bytes,
                      orig_len: int, iface: int)
                      iter_packets(path) -> Iterator[RawPacket]   # classic pcap (us/ns, both endians) + pcapng
                      class PcapWriter(path, linktype=1, snaplen=65535): write(ts, data); close(); context manager
                      sha256_file(path) -> str; detect_format(path) -> "pcap"|"pcapng"
capture/link.py       @dataclass UdpDatagram(frame_no, ts, src_ip, src_port, dst_ip, dst_port, payload: bytes,
                      eth_src: str|None, eth_dst: str|None)
                      class UdpExtractor: feed(RawPacket) -> list[UdpDatagram]  (IPv4 fragment reassembly,
                      timeouts; link types 0,1,101,108,113,228,276; 802.1Q/QinQ); stats dict
                      build_udp_frame(src_ip, src_port, dst_ip, dst_port, payload, src_mac=..., dst_mac=...)
                      -> bytes (Ethernet II + IPv4 + UDP with checksums)  # used by synth + redaction
```

## analysis/, findings/ (owner: integrator)

```
analysis/passive.py   class PassiveAnalyzer(own_addrs=set()): feed(udp: UdpDatagram, msg: BacnetMessage, own=False);
                      finish() -> PassiveState
analysis/analyze.py   analyze_file(path, vantage_override=None, known_writers=()) -> Result
findings/catalogue.py CATALOGUE: dict[id, FindingSpec]; make_finding(id, subject, *, severity=None,
                      confidence=None, evidence=(), thresholds=(), **fmt) -> Finding
findings/thresholds.py THRESHOLDS: dict[name, (value, provisional: bool)]
findings/passive.py   evaluate_passive(state, vantage) -> (findings, checks_not_performed)
findings/active.py    evaluate_active(devices, bbmds, topology, scan_stats) -> findings
```

## active/ (owner: active agent)

```
active/iface.py       @dataclass Iface(name, ip, netmask, prefix, broadcast, is_loopback, is_up, has_default_route,
                      wireless_guess); list_interfaces(); auto_pick(ifaces) -> (Iface|None, ranked list, reasons)
active/transport.py   class BacnetTransport(bind_ip, port, *, broadcast_targets=None, rate=RateLimits, cancel=Event):
                      exclusive bind; send_unicast(frame, addr); send_broadcast(frame); recv(timeout) ->
                      (bytes, (ip,port))|None; every send passes txguard.check_tx; counts into Budget
active/scan.py        @dataclass ScanOptions(...); class Scanner(transport, options, progress=cb, cancel=Event):
                      plan() -> Budget; run() -> Result
active/bbmd.py, topology.py, active/listen.py
testing/sim.py        Simulator: virtual devices / BBMDs on 127.0.0.1 (distinct ports), fault injection
testing/synth.py      synthetic pcap builder for tests and demos
```

## report/ (owner: report agent)

```
report/branding.py    @dataclass Branding(org="", prepared_by="", site="", client="", logo_path=None,
                      accent="#1f4e79"); Branding.load(path)
report/merge.py       merge_results(results: list[Result]) -> Result
report/diff.py        diff_results(old: Result, new: Result) -> dict (devices added/removed/changed,
                      findings new/resolved/persisting)
report/html.py        render_html(result: Result, branding: Branding, diff: dict|None=None) -> str
report/terminal.py    render_terminal(result: Result, color: bool=False) -> str
report/redact.py      redact_result(result, key: bytes) -> Result; redact_pcap(in_path, out_path, key) -> stats
```

## Entry points (owner: integrator)

`cli.py` (argparse, subcommands scan/listen/analyze/report/audit/gui), `profile.py` (.bhprofile), `gui/app.py`.
