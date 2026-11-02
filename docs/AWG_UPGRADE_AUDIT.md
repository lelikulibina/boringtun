# AWG protocol upgrade — audit and implementation log

## Scope

Upgrade the BoringTun fork from the `awg-2.0-extensions` baseline to the current stable AmneziaWG protocol implemented by the official `amnezia-vpn/amneziawg-go` repository. The official implementation is the behavioral reference. Do not assume that a feature mentioned in documentation is implemented until its wire behavior has been verified against the reference source and cross-implementation tests.

## Branch policy

- This work is isolated from `awg-2.0-extensions`, `master`, and all other existing branches.
- This branch (`awg-audit`) is for baseline inspection, reference-version pinning, protocol mapping, and test-plan preparation.
- Each implementation stage must use its own branch, based on the last reviewed stage.
- Integration happens only in a dedicated integration branch.
- The final, fully tested result must be delivered in a separate `awg-final-release` branch.
- Never merge unverified changes into the next stage or into the final branch.

## Reference baseline — initial observations

The official repository's current `master` README documents AWG 3+ features, including:

- Header protection using a server-side `HeaderProtectionKey`, with a stated requirement that S1–S4 be at least 12.
- Content padding using `ContentPaddingAddition`.
- Configurable timing parameters: `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, and peer `PersistentKeepalive`.
- Junk packets Jc/Jmin/Jmax.
- S1–S4 message padding and H1–H4 header ranges.
- Custom signature packets I1–I5 and their byte/random/digit/character/timestamp template tags.

The official `go.mod` declares module path `github.com/amnezia-vpn/amneziawg-go/v3` and Go 1.25.0. This confirms that the current default branch is a v3 line, but it does **not** by itself identify a stable release tag or prove the exact wire compatibility level. The exact release tag and commit SHA must be pinned before protocol implementation begins. Do not label the target as 3.1 without verifying the official tags/releases and source history.

## Initial target-branch inventory

Inspected on `awg-2.0-extensions`:

- `boringtun/src/device/api.rs` contains UAPI support for Jc/Jmin/Jmax, S1–S4, and H1–H4; H1–H4 accept a single value or inclusive range. It publishes the UAPI socket under both WireGuard and AmneziaWG runtime directories.
- The UAPI parser recognizes I1–I5 but currently treats them as no-op parameters. This is a functional gap relative to the current official README's custom signature packet configuration.
- `boringtun/src/noise/mod.rs` contains AWG packet-handling tests, H1–H4 range tests, junk packet tests, and protocol-imitation tests. Existing imitation and Jd behavior are fork-specific and must be preserved unless tests show a conflict.
- `README.md` remains the upstream BoringTun README and does not yet document the fork's AmneziaWG behavior.
- Workspace is a Rust Cargo workspace with `boringtun` and `boringtun-cli`.

This is a preliminary inventory, not a complete protocol audit. Inspect the full dependency graph, configuration types, handshake/session/transport paths, timers, packet serialization, CLI and FFI surfaces before implementation.

## Mandatory protocol audit matrix

For every official feature, record: source file and symbol in the Go reference; wire format and state transitions; matching Rust code (or absence); config/UAPI exposure; compatibility constraints; unit tests; cross-implementation test result.

1. Baseline WireGuard handshake and transport behavior.
2. H1–H4 magic header ranges, validation, random selection, and packet classification.
3. S1–S4 padding, size bounds, and interaction with MTU.
4. Jc/Jmin/Jmax generation and pre-handshake sequencing.
5. I1–I5 template parsing, expansion, sequencing, retransmission, and timing.
6. AWG 3+ header protection, key lifecycle, nonce construction, and authenticated packet handling.
7. AWG 3+ content padding and its negotiation/compatibility semantics.
8. AWG 3+ timing parameters and their effect on handshake, keepalive, rekey, and rejection.
9. Cookie behavior and any disable-cookie mode.
10. Any trailer/random-trailer behavior present in the pinned reference source.
11. UAPI/config parsing, serialization, defaults, validation, and error behavior.
12. Existing fork-only imitation features (DNS, QUIC, SIP, STUN, browser profiles, Jd) and their regression/interaction behavior.
13. Vanilla WireGuard regression and platform-specific behavior.

## Required test strategy at every stage

A successful build or handshake alone is insufficient. Each stage must run:

- Formatting, linting, compilation, and all existing Rust tests.
- New unit tests for every changed parser, serializer, packet transform, timer, and boundary condition.
- Negative tests for malformed config, invalid ranges, truncated packets, invalid authentication, oversized payloads, and MTU edges.
- BoringTun-to-BoringTun integration tests.
- Cross-implementation tests in both directions: BoringTun client to official amneziawg-go server, and official client to BoringTun server.
- Real tunnel traffic in both directions: ICMP, TCP, and UDP, including large transfers, MTU checks, packet loss/recovery, reconnect, and long-running traffic.
- Captured logs, exact config (with private keys redacted), version/commit identifiers, commands, and measured throughput/latency/loss.

Real cross-implementation tests require two independently running endpoints and a privileged network test environment (TUN/interface and routing permissions). If such an environment is unavailable, mark those tests as BLOCKED; never report them as passed based on mocks or in-process tests.

## Stage gates

- Audit gate: pinned official release/commit, completed source-to-source feature matrix, and baseline test results.
- Feature gate: each protocol feature has implementation, unit tests, and cross-implementation evidence before the next feature stage begins.
- Integration gate: all stage branches reviewed and merged only into the integration branch; run the complete regression suite.
- Final gate: create `awg-final-release` as a separate branch only after integration passes. Repeat all tests against that exact branch and publish a final report.

## Progress log

### 2026-11-02 — start

- Created isolated branch `awg-audit` from `awg-2.0-extensions`.
- Confirmed repository write permission.
- Confirmed official default branch currently declares module path `/v3` and README documents AWG 3+ settings.
- Initial gap found: I1–I5 are accepted as no-op in target UAPI, while the official README documents custom signature packet support.
- No protocol implementation changes have been made yet.
- Next: pin the exact official stable release/tag and commit; inspect all relevant Go and Rust source paths; complete the feature matrix and establish a baseline test harness.
