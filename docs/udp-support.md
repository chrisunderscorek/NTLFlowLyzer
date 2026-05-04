# UDP Support Patch

This fork is based on `ahlashkari/NTLFlowLyzer` and carries the local UDP patch
that was used for malware PCAP processing on the `malware` AWS host.

## User Story

As a security researcher processing malware sandbox PCAPs, I need a flow export
that includes both TCP and UDP traffic, so that downstream labeling, inventory
building, and family-level analysis can see the complete network behavior of a
sample.

In the malware workflow that motivated this patch, NTLFlowLyzer was used as one
of the NetFlow generators before PCAP metadata annotation and endpoint labeling.
The upstream parser only emitted TCP flows. That meant UDP activity was silently
absent from the NTLFlowLyzer output even when it was present in the original
PCAP. For malware analysis this is a material gap: UDP can carry DNS lookups,
service discovery, C2 bootstrap traffic, or short-lived application traffic that
helps explain later TCP connections.

The desired behavior is not to redefine every TCP feature for UDP. The desired
behavior is to keep the existing NTLFlowLyzer output shape usable while adding
UDP rows and making TCP-only fields explicitly not applicable.

## Goals

- Preserve the original CSV shape as much as possible.
- Continue processing TCP flows with the original behavior.
- Add UDP flows without forcing downstream scripts to handle a separate schema.
- Make batch processing usable on Linux/macOS paths, not only Windows-style paths.
- Keep the fork installable next to the original package by renaming the Python
  package and console script.

## Non-Goals

- This patch does not add UDP-specific statistical features beyond what the
  existing packet/flow model can already calculate.
- This patch does not reinterpret TCP handshake, TCP flag, TCP window, sequence,
  or acknowledgement features for UDP.
- This patch does not change the intended behavior of TCP flow extraction.
- This patch does not make batch mode recursive; malware-family directory
  iteration is handled by the helper script.
- This patch does not add protocol parsing for DNS, QUIC, DTLS, or application
  payloads. It only ensures UDP packets become transport-layer flows.

## Summary Of Changes

- Rename the installable package from `NTLFlowLyzer` to `NTLFlowLyzer-UDP`.
- Rename the import package from `NTLFlowLyzer` to `NTLFlowLyzer_udp`.
- Rename the console command from `ntlflowlyzer` to `ntlflowlyzer_udp`.
- Accept `dpkt.udp.UDP` packets in the flow capturer in addition to TCP.
- Emit neutral packet-level values for TCP-only packet fields on UDP packets.
- Emit `NaN` for TCP-only derived features on UDP flows.
- Make batch file discovery deterministic and path-portable.
- Add a generic helper script for one-directory-per-family malware datasets.

## Release Strategy

This branch is intended as the first reviewable release of the local UDP fork. It
uses a separate package and console command:

```bash
ntlflowlyzer_udp -c YOUR_CONFIG_FILE
```

That makes the fork easy to install and test next to the original upstream
`ntlflowlyzer` command.

A later, more upstream-compatible patch can keep the original package and command
and add an explicit option instead:

```bash
ntlflowlyzer --udp -c YOUR_CONFIG_FILE
```

In that follow-up design, TCP-only behavior would remain the default and UDP
flows would be emitted only when `--udp` is passed. This keeps the first release
small and reviewable while leaving a clean path toward an upstream-style feature
flag.

## Package And CLI

- Python package: `NTLFlowLyzer_udp`
- Distribution name: `NTLFlowLyzer-UDP`
- Version: `0.1.0.post1`
- Console script: `ntlflowlyzer_udp`

The package rename avoids overwriting an installed upstream `NTLFlowLyzer`. This
is useful during review and comparison because a user can keep the original tool
installed while testing the UDP fork.

## Packet Parsing

File:

- `NTLFlowLyzer_udp/network_flow_capturer/network_flow_capturer.py`

The upstream parser only creates flows for `dpkt.tcp.TCP`. This fork accepts:

- `dpkt.tcp.TCP`
- `dpkt.udp.UDP`

For TCP packets, the existing values are preserved:

- source and destination ports
- TCP flags
- sequence number
- acknowledgement number
- TCP window size
- TCP payload length
- transport header length

For UDP packets, the fork still creates a normal `Packet` object but fills TCP-only
packet fields with neutral values:

- `window_size = 0`
- `tcp_flags = 0`
- `seq_number = 0`
- `ack_number = 0`

The UDP source port, destination port, payload length, and header length come from
the UDP layer.

This keeps the existing CSV columns stable. Downstream tools that already expect
the NTLFlowLyzer schema do not need a separate UDP schema branch.

## Feature Extraction

File:

- `NTLFlowLyzer_udp/feature_extractor.py`

The original feature extractor assumes many TCP-specific fields are meaningful for
all flows. For UDP flows this fork emits `NaN` for TCP-only features instead of
logging extraction errors for every UDP row.

Currently treated as TCP-only:

- all features from the `flag_related` feature module
- `delta_start`
- `handshake_duration`
- `handshake_state`
- `fwd_init_win_bytes`
- `bwd_init_win_bytes`

All non-TCP-specific features continue to be extracted normally for UDP flows.

The key design choice is explicit non-applicability. A UDP value of `NaN` for
`handshake_duration` is more honest and easier to audit than a fabricated numeric
value, while a packet-level zero for TCP flags/window/sequence values preserves
the existing `Packet` object contract.

## Batch Mode

File:

- `NTLFlowLyzer_udp/__main__.py`

Batch mode now:

- accepts only files ending in `.pcap` or `.pcapng`
- skips directories
- sorts input file names for deterministic output order
- creates the output directory if needed
- builds output file paths with `pathlib`

The batch mode remains non-recursive. For a malware-family dataset, call it once
per family directory or use `scripts/process_subdir_udp.sh`.

Example config for one family directory:

```json
{
  "batch_address": "/data/pcaps/zloader",
  "batch_address_output": "/data/ntlflowlyzer_udp/zloader",
  "number_of_threads": 12,
  "label": "zloader"
}
```

## Helper Script

File:

- `scripts/process_subdir_udp.sh`

The helper iterates one level of malware-family directories, creates a temporary
JSON config for each family, and runs `ntlflowlyzer_udp -b -c <config>`.

Example:

```bash
OUT_BASE=/data/ntlflowlyzer_udp_out \
THREADS=12 \
scripts/process_subdir_udp.sh /data/malware-pcaps
```

Set `SKIP_EXISTING=1` to avoid rerunning labels where the output directory already
exists.

## Compatibility Notes

- TCP behavior is intended to stay unchanged.
- UDP support has schema compatibility as its priority; TCP-only output columns
  remain present.
- Downstream consumers should treat `NaN` TCP-only feature values on UDP rows as
  "not applicable", not as missing parser output.
- The original documentation still describes upstream TCP-focused behavior unless
  this patch document says otherwise.

## Review Notes

Suggested review focus:

- Confirm TCP code paths still use the same packet fields as upstream.
- Confirm UDP packet fields use UDP ports, payload length, and header length.
- Confirm TCP-only features are the only features forced to `NaN` for UDP.
- Confirm the package rename is acceptable for this fork. If the project prefers
  a single upstream package instead, the UDP logic can be kept while reverting the
  package and console-script rename.
- Confirm batch mode should include `.pcapng`. The original README says PCAPNG
  may require conversion, but the server patch accepted both extensions. If that
  is too broad, the extension list can be reduced to `.pcap`.

Minimal smoke checks:

```bash
python3 -m compileall -q NTLFlowLyzer_udp
ntlflowlyzer_udp -h
ntlflowlyzer_udp -b -c examples/one-family-config.json
```

The last command requires a real PCAP directory and should be validated on a
small sample before running on a large malware corpus.
