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

## Pinned reference

- Repository: https://github.com/amnezia-vpn/amneziawg-go
- Stable tag: `v3.1.20260828`
- Tag commit: `b5928efb6ca19f0153958460c3d141f04abc5c2e`
- The tag points at the same commit currently observed at the official `master` head.
- Module path at that commit: `github.com/amnezia-vpn/amneziawg-go/v3`
- The official `go.mod` declares Go 1.25.0.

All subsequent comparisons must use the pinned tag/commit, not a moving `master` reference. Re-pin only if a newer stable official tag is found before implementation starts; record the reason and the new commit explicitly.

## Official AWG 3.1 protocol surface confirmed in source

The official README, UAPI, device state, send/receive pipeline and helper files confirm these feature groups:

1. **Header protection** — `header_protection_key`; a ChaCha20 stream cipher is derived using the per-packet salt. Receive-side classification decrypts the type hash, and packet fields are unmasked in the receive path. The README requires S1–S4 to be at least 12 when header protection is enabled.
2. **Content padding** — `content_padding_addition`; a configurable range used for additional padding of transport payloads, constrained by the peer's UDP window/MTU.
3. **Timing ranges** — `rekey_after_time`, `rekey_timeout`, `reject_after_time`, `keepalive_timeout`, `max_handshake_attempts`, and peer `persistent_keepalive`.
4. **Random trailers** — `random_trailers`; handshake and cookie packets may include random trailing bytes; receive-side packet classification accounts for this mode.
5. **Cookie control** — `disable_cookies`; the pinned commit specifically changes under-load handling so cookie-based load mitigation is disabled consistently when this option is set.
6. **I1–I5 custom signature packets** — configured as transformation chains and sent before handshake initiation. The source parser supports tags `b`, `t`, `r`, `rc`, `rd`, `d`, `ds`, and `dz`; implementation must reproduce the pinned source semantics and validate lengths safely.
7. **Existing AWG 2.0 fields** — Jc/Jmin/Jmax, S1–S4, H1–H4 continue to be represented in UAPI and the packet pipeline.
8. **Wire behavior** — the reference send/receive pipeline applies prefix padding, header protection, optional random trailers, content padding, and signature/junk sequencing at specific points. Reproducing only config parsing is insufficient.

Relevant reference source files include `device/noise-protocol.go`, `device/send.go`, `device/receive.go`, `device/timers.go`, `device/device.go`, `device/peer.go`, `device/uapi.go`, and `device/obf*.go`.

## Initial target-branch inventory

Inspected on `awg-2.0-extensions`:

- `boringtun/src/device/api.rs` contains UAPI support for Jc/Jmin/Jmax, S1–S4, and H1–H4; H1–H4 accept a single value or inclusive range. It publishes the UAPI socket under both WireGuard and AmneziaWG runtime directories.
- The UAPI parser recognizes I1–I5 but currently treats them as no-op parameters. The official reference parses and stores transformation chains for all five packets and emits them before handshake initiation.
- `boringtun/src/noise/amnezia.rs` contains S1–S4, Jc/Jmin/Jmax, Jd and fork-specific DNS/QUIC/SIP/STUN imitation. It does not currently expose the AWG 3.1 header-protection key, content-padding range, timing ranges, random-trailer flag, or cookie-disable flag.
- `boringtun/src/noise/handshake.rs` contains H1–H4 range handling and random tag selection. The inspected handshake path writes the randomized header value, but no AWG 3.1 header-protection transform is present in this file.
- `boringtun/src/noise/session.rs` implements WireGuard AEAD sessions and replay-counter validation; the inspected structure has no AWG 3.1 content-padding configuration or transport header-protection integration.
- `boringtun/src/noise/timers.rs` uses fixed WireGuard timing constants; configurable AWG 3.1 timing ranges are not represented in the inspected timer configuration.
- `boringtun/src/noise/mod.rs` contains AWG packet-handling tests, H1–H4 range tests, junk packet tests, and protocol-imitation tests. Existing imitation and Jd behavior are fork-specific and must be preserved unless tests show a conflict.
- `README.md` remains the upstream BoringTun README and does not yet document the fork's AmneziaWG behavior.
- Workspace is a Rust Cargo workspace with `boringtun` and `boringtun-cli`.

This inventory is preliminary. In particular, every receive/send packet offset, UAPI transaction boundary, timer transition and MTU calculation must be reviewed before implementing changes.


## Detailed AWG 3.1 source mapping — next protocol stages

The following behavior was checked directly against the pinned reference tag `v3.1.20260828`:

### Header protection

- Reference state: `device/device.go` stores a 32-byte `HeaderCipherKey` behind an RW lock; `device/noise-protocol.go` implements `HeaderProtectionCipher(salt)` as ChaCha20 with that key and the supplied 12-byte nonce/salt. A zero key disables the transform.
- Send ordering: `device/send.go` first creates the S1-S4 random prefix. Its first 12 bytes are passed as the ChaCha20 nonce. For handshake-initiation, response and cookie packets, MACs are added before the packet bytes are XORed with the ChaCha20 stream. For transport, the encrypted packet content is already produced and only the 16-byte transport header is XORed.
- Receive ordering: `device/receive.go` derives the same stream from the first 12 bytes, XORs a zero 4-byte buffer to recover the masked type, classifies using the recovered type, unmasks the first type field, then continues the stream over the remaining fixed-size handshake bytes or transport header.
- Configuration rule: `device/uapi.go` rejects a nonzero header-protection key unless **all four** S1-S4 prefix sizes are at least 12 bytes. The Rust implementation must enforce this atomically with the key and all four S values; partial updates must not leave an invalid live configuration.
- Current Rust gap: there is no equivalent header-protection key, ChaCha20 stream transform, or inverse receive transform in the inspected BoringTun packet paths.

### Content padding and random trailers

- Reference content padding: `device/send.go:randomPaddingAddition` picks a value from `content_padding_addition`, then caps it to the peer's learned `udpWindow - packetSize`. If the range is unset, it returns a sentinel so the sender may try random trailers or ordinary MTU alignment. A configured addition takes precedence over random trailers.
- Padding bytes are zero-filled **before AEAD encryption**. The receiver's IP packet length validation truncates the decrypted IP packet to the length in its IPv4/IPv6 header; no separate content-padding length field is negotiated.
- Random trailers are separate from encrypted content padding. Handshake initiation, response and cookie replies append random bytes after their fixed WireGuard message. Transport may append random bytes after the encrypted payload when content-padding addition is unset. The peer/device UDP-window bound is used to avoid exceeding the observed or default UDP payload size.
- Receive classification: with `random_trailers=1`, fixed-size initiation/response/cookie messages may be longer than their base size; the receiver classifies the message at the S-prefix offset and truncates the handshake packet back to its fixed protocol size. Transport is variable-length already and accepts a datagram at least as large as its minimum.
- Current Rust gap: the inspected BoringTun code has S-prefix padding and MTU alignment but no configurable content-padding range or random-trailer acceptance/generation.

### Timing controls

- `rekey_after_time` overrides the initiator key-refresh age; `rekey_timeout` participates in retransmit/new-handshake timing; `reject_after_time` determines key-chain expiry; `keepalive_timeout` adjusts new-handshake timing and the receiving-side rekey margin; `max_handshake_attempts` controls how many retransmissions occur before staged packets are flushed.
- The reference uses `UintRange.PickOne()` for random selection where the call site needs a single duration, but uses the lower/upper bound deliberately for conservative timeout calculations (e.g. keepalive/rekey timeout margins and key expiry).
- Current Rust gap: `noise/timers.rs` uses fixed WireGuard timing constants and does not expose these ranges through UAPI.

### Cookie control

- In `device/receive.go`, `disable_cookies` bypasses the entire under-load branch, including MAC2 cookie challenge and the associated source rate limiter. This is not merely a cosmetic switch: it trades the cookie-based load-shedding path for reduced per-packet work and greater exposure to unauthenticated handshake processing.
- Current Rust gap: there is no equivalent UAPI flag or matching under-load behavior switch.

### I1-I5 real interop configuration

- The namespace interop script now includes I1-I5 templates in its shared AWG UAPI block: fixed bytes, timestamp, random bytes, random letters and random digits. This exercises official-client signature emission into the BoringTun server path when the namespace test runs.
- This is a test configuration change only; no successful run has been observed yet. The reverse role (BoringTun sender to official server) and real TCP/UDP payload transfer are still not verified.

## Mandatory protocol audit matrix

For every official feature, record: source file and symbol in the pinned Go reference; wire format and state transitions; matching Rust code (or absence); config/UAPI exposure; compatibility constraints; unit tests; cross-implementation test result.

1. Baseline WireGuard handshake and transport behavior.
2. H1–H4 magic header ranges, validation, random selection, and packet classification.
3. S1–S4 padding, size bounds, and interaction with MTU.
4. Jc/Jmin/Jmax generation and pre-handshake sequencing.
5. I1–I5 template parser and every official tag, expansion, sequencing, retry semantics, and timing.
6. AWG 3.1 header protection: key lifecycle, nonce/salt construction, fields protected, order relative to MAC calculation and padding, and receive-side inverse transform.
7. AWG 3.1 content padding: selection range, padding algorithm, peer UDP window/MTU handling, and removal on receive.
8. AWG 3.1 timing parameters and their effect on handshake, keepalive, rekey, reject, and maximum attempts.
9. Cookie behavior, under-load handling, and disable-cookie mode.
10. Random trailer generation, size bounds, and receive-side packet classification.
11. UAPI/config parsing, serialization, defaults, validation, atomicity, and error behavior.
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

### 2026-11-02 — start and initial source comparison

- Created isolated branch `awg-audit` from `awg-2.0-extensions`.
- Added this audit and continuity document.
- Pinned official stable tag `v3.1.20260828` to commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`.
- Confirmed official module path `/v3` and Go 1.25.0.
- Confirmed initial gaps: I1–I5 are no-op in target UAPI; target config lacks AWG 3.1 header protection, content padding, configurable timings, random trailers, and disable-cookie support.
- Confirmed official I-packet parser supports eight transform tags, beyond the simplified examples in the README.
- No protocol implementation changes have been made yet. The audit branch contains documentation only.
- Next: complete detailed source-to-source mapping and establish baseline build/test results; then create a separate implementation branch from the reviewed audit snapshot.

### 2026-11-02 — interoperability harness stage

- Created implementation/test-infrastructure branch `awg-3.1-core` from the isolated audit branch; the original source branches remain untouched.
- Expanded the GitHub Actions branch filters to cover isolated `awg-*` work branches.
- The original `scripts/awg-go-interop.sh` was restored after an attempted reverse-role extension produced malformed shell syntax. A narrow, syntax-checked change now adds I1-I5 templates to its UAPI config. It still validates only the amneziawg-go-client to BoringTun-server path and ICMP traffic; reverse-role and TCP/UDP coverage remain outstanding.
- Added an Ubuntu CI job that builds BoringTun, builds the exact official `v3.1.20260828` tag, and runs the existing namespace-based interop harness (currently one direction, ICMP).
- Opened draft PR #1 against `awg-2.0-extensions` only as a review/CI checkpoint: https://github.com/lelikulibina/boringtun/pull/1. It is explicitly marked draft and must not be merged.
- At this checkpoint, GitHub's status endpoint has not returned any checks/workflow runs. Therefore the new harness and CI job are **not yet verified as executed**. Do not mark this stage passed until the workflow result is observed and failures are fixed.
- No AWG 3.1 protocol implementation is included in this branch; it prepares audit and CI infrastructure. The interop harness extension was deliberately reverted before it could contaminate the test baseline.
- Next: obtain a green baseline CI/interoperability run; complete the per-feature source-to-source audit; then implement the first AWG 3.1 protocol feature in its own branch with unit tests and cross-implementation checks.

### 2026-11-02 — correction of interop harness status

- Reverted an attempted modification of `scripts/awg-go-interop.sh` after inspection exposed malformed shell syntax and duplicated trailing shell text. The original script from `awg-2.0-extensions` is restored; the unintegrated Python traffic helper was deleted.
- The CI job tests only the original official-client-to-BoringTun-server path and ICMP. Reverse-role and TCP/UDP checks remain outstanding.
- No protocol implementation changes are included in this branch.
- CI has not returned workflow runs or status checks for this branch. Do not treat build or interop as passed until real results appear.

### 2026-11-02 — I-packet implementation stage

- Created separate stage branch `awg-i-packets-rebased` from the updated `awg-3.1-core` stage.
- Implemented a bounded parser and encoder for all eight official I-packet transforms: `b`, `t`, `r`, `rc`, `rd`, `d`, `ds`, and `dz`.
- Connected I1-I5 to UAPI set/get. I-packet values are parsed and validated instead of silently ignored; an empty value clears a slot.
- Added a public `AmneziaConfig::with_signature_packet` builder for embedders that configure the library without UAPI.
- Added ordered pre-handshake emission: configured I1..I5 datagrams, then existing imitation datagrams/Jc junk, then Noise initiation. Too-small output buffers do not consume a queued signature packet.
- Added unit tests for all transform tags, output order/alphabet/bounds, UAPI merge/clear/rejection, pre-handshake order, and retry-safe buffer handling.
- Added I1-I5 template values to the real namespace interop configuration so the official client will emit signature datagrams before its handshake when the harness runs.
- Draft PR #3 opened against the preceding stage branch `awg-3.1-core`: https://github.com/lelikulibina/boringtun/pull/3. Superseded PR #2 was closed; do not merge it.
- CI results are still absent from the Actions API for the current PR head. Build, formatting, clippy and unit tests therefore remain **unverified**, not passed.
- Next: fix any CI/compiler findings; add independent interop tests for both endpoint roles and real TCP/UDP payload transfer; run against the pinned official release. Then proceed to header protection, content padding, timing, trailers and cookie behavior in separate stage branches.

### 2026-11-02 — validation environment checkpoint

- PR #3 is open as draft, targets `awg-3.1-core`, and GitHub currently reports the branch mergeable/clean. This is only a mergeability result, not a test result.
- The repository Actions API currently reports `total_count=0` workflow runs for the repository; the PR head has no workflow runs and no commit status checks. CI therefore has not executed or reported a result.
- A local clone attempt failed because the execution environment cannot resolve `github.com`; `rustc` and `cargo` are not installed in that environment. No local Cargo build or test can be honestly reported.
- The shell block used to construct the interop UAPI settings was separately checked with `bash -n`; the full namespace harness has not been run.
- Required next action before closing the I-packet stage: make GitHub Actions actually execute (verify repository Actions settings or run the workflow in an enabled runner), fix all compiler/test findings, then run the namespace interop test with I1-I5 and confirm the actual handshake/ICMP result. Add reverse-role and TCP/UDP tests before considering the stage complete.

### 2026-11-02 — static review follow-up

- A second source review found two borrowed-length arithmetic expressions in the I-packet encoder that would fail Rust type checking (`usize + &usize`). Both the random-digit and data-size branches now dereference the borrowed transform length.
- This is a static-review correction only. There is still no compiler/test output from CI or a local Rust toolchain, so the branch is **not build-verified**.
- Added `workflow_dispatch` to the workflow on `awg-3.1-core`, so a maintainer can manually run the complete validation workflow from the Actions tab after confirming repository Actions are enabled. Push and pull-request triggers remain in place.
- Repository-wide Actions query still reports zero runs. This cannot be resolved through the available GitHub connection because it exposes read-only repository/workflow inspection, not the repository Actions enablement settings or a workflow-dispatch write operation.

- Expanded the ordered-emission unit test to configure all five slots and assert I1, I2, I3, I4, I5 are emitted in order before Jc and the Noise initiation. The test is added but has not run because CI remains unavailable.

- Corrected the workflow's interop job comments/name: they had claimed TCP/UDP payload coverage that the current shell harness does not implement. The job is now explicitly described as handshake + ICMP only; reverse-role and TCP/UDP remain open tasks.

### 2026-11-02 — I1-I5 static lifecycle and UAPI review

- Re-read the full I1-I5 implementation path: AwgParams transaction accumulation/merge, api_set, Device::set_obfuscation, Tunn::set_obfuscation, format_handshake_initiation, and advance_amnezia_junk.
- Confirmed statically that I1-I5 are queued in slot order and emitted as separate datagrams before imitation datagrams, Jc packets, and the Noise initiation. The queue is retained on a too-small output buffer and is cleared only after the initiation is successfully written.
- Confirmed statically that a new handshake/retry rebuilds the pre-handshake queue; an already pending queue is drained rather than duplicated. Updating AWG settings propagates the new config to existing peers and clears stale pending pre-handshake state.
- Confirmed UAPI device-level values are accumulated and validated as one transaction, partial updates preserve unspecified I slots, an explicitly empty iN= clears only that slot, and invalid templates reject the transaction before commit. Existing protocol-imitation settings are preserved by cloning and merging the current AmneziaConfig.
- Confirmed all eight implemented transforms have the expected empty-source behavior for standalone signature datagrams: d and ds produce no bytes; dz N emits N zero bytes; timestamp is four-byte big-endian Unix seconds; random bytes/letters/digits use the expected output lengths and alphabets. This remains a source review, not a compiler or wire-level result.
- Official project documentation describes I1-I5 as separate pre-handshake signature packets, in I1..I5 order, and recommends configuring them client-side; the current harness configures both peers but only exercises the official-client-to-BoringTun-server initiation path. See https://github.com/amnezia-vpn/amneziawg-go and https://docs.amnezia.org/documentation/instructions/amneziawg-signature/.
- No code changes were needed from this static pass. The stage remains BLOCKED pending actual Rust build/tests and pinned-reference interop execution. Reverse-role and TCP/UDP traffic coverage remain outstanding.

### 2026-11-02 — upstream I-chain and responder coverage follow-up

- Compared the Rust encoder/parser directly with the pinned amneziawg-go v3.1.20260828 sources: device/send.go, device/obf.go, device/obf_bytes.go, device/obf_timestamp.go, device/obf_rand.go, device/obf_randchars.go, device/obf_randdigits.go, device/obf_data.go, device/obf_datastring.go, and device/obf_datasize.go. The eight tags and the zero-length source semantics used by I1-I5 match the reference call site.
- Verified the reference sends each configured I-chain as its own datagram, iterating the device.ipackets array in order before JunkPackets() and the Noise initiation. The Rust queue follows that order (with this fork's protocol-imitation datagrams between I packets and Jc, which is a fork extension rather than upstream behavior).
- Confirmed UAPI get serializes only configured I1-I5 templates in index order. Empty configured slots are omitted, matching the reference's device-level configuration behavior.
- Added a regression test that configures I1 on an AmneziaConfig marked as_responder and asserts the responder emits the padded Noise initiation directly, not the standalone I1 packet. The test has been committed but has NOT been compiled or run.
- New implementation commits: 3ad6c4260f1b7bf9afa7adbbc528dfcc81957edc (test addition), f471565f49f1eb22ebfbc0a92687b7efe1ea6a8f (bounds-safe assertion ordering). No protocol implementation changes were made in this follow-up.
- Validation remains BLOCKED: GitHub Actions has no recorded runs/statuses, local Rust toolchain is unavailable, and the namespace interop harness has not executed. Do not advance to Header Protection until the full build/test gate and real bidirectional interop pass.

- Follow-up review caught and removed a redundant assertion in the newly added responder regression test; the test now checks the padded initiation length before reading its message type, so an unexpected short I1 datagram fails cleanly instead of indexing out of bounds. Latest code commit: 9c9b6677e72a44f3723cfec4abb5b3d53c94120f. Still uncompiled/unrun.


### 2026-11-02 — I-chain parser edge-case parity review

- Re-opened the pinned upstream implementations for all eight I-chain transforms and the chain parser. Confirmed the Rust parser follows the reference's tag extraction model: it scans successive angle-bracket groups, uses the first whitespace-delimited argument, ignores text outside tags, and accumulates errors for malformed/unknown tags. The t, d, and ds builders intentionally ignore their optional value just as the Go builders do.
- Confirmed <b ...> handling matches the upstream lowercase 0x prefix removal and hex decoding. Timestamp encoding uses the same four-byte big-endian Unix-seconds truncation. Random-character and digit alphabets match the reference; modulo mapping is the same.
- Reviewed the intentional safety divergence for length-bearing tags: Rust rejects negative lengths and bounds each and total packet length to the maximum IPv4 UDP payload. The Go constructors use signed strconv.Atoi without equivalent bounds; negative lengths can later panic during slicing/encoding. Accepting those values would not provide a functioning interoperable packet, so the Rust validation is a deliberate hardening rather than a wire-format deviation.
- Confirmed the dz big-endian source-length field is all zero for I1-I5 because upstream calls each I-chain with a nil source slice. The same nil-source call means d emits zero bytes and ds emits an empty raw-base64 string.
- No additional wire-format mismatch was found in this pass. No code change was justified. Remaining unverified items include compilation, parser/UAPI runtime tests, and actual cross-implementation packet capture; this static review does not close the I-packet stage.


### 2026-11-02 — I-chain parser error accumulation fix

- A closer review of `SignaturePacket::parse` found that the numeric-length branch used `?` inside the tag match. That returned from the whole parser on the first malformed length, despite the surrounding implementation and upstream Go parser accumulating independent tag errors.
- Changed the length branch to keep the parse failure as a per-tag `Result`, allowing the parser to continue and report subsequent unknown/malformed tags in the same response. Wire encoding and accepted valid templates are unchanged.
- Added a regression test with `<r nope><unknown 1>` asserting that both errors are reported. The change is committed but remains uncompiled and unexecuted because no Rust toolchain/CI run is available.


### 2026-11-02 — I-chain pending-queue reconfiguration regression

- Added a regression test that emits the first packet from an old I1/I2 sequence, changes the tunnel's obfuscation configuration while I2 is pending, and asserts the next emitted datagram is the new I1 template. This guards against stale signature datagrams escaping after a live UAPI/config update.
- The test exercises the public tunnel reconfiguration path (set_obfuscation) and the actual pre-handshake emission path; it is not a mock of the queue.
- Commit: 0d231ead9c029c4c8e0ff432f3ed63668f2151df.
- Static inspection only: Rust formatting, compilation, unit tests, CI and live interop remain blocked by the unavailable Rust toolchain and absent GitHub Actions runs. The new test must not be counted as passed until executed.


- Added a second queue-lifecycle regression: a forced handshake retry between I1 and I2 must drain the already-generated sequence (I2 next), must not regenerate/replay I1, and must then emit the Noise initiation. Commit: a8a4f50ae074202058a7c033965788ce03c94993. Like the other new test, this is committed but not executed.


### 2026-11-02 — GitHub Actions trigger attempt and scope correction

- Updated `.github/workflows/on-push.yaml` on `awg-i-packets-rebased`: added `workflow_dispatch` and corrected the interop job description/name to state its actual coverage (handshake + ICMP only). The previous workflow comment claimed TCP/UDP coverage that the checked-in `scripts/awg-go-interop.sh` does not implement; that claim is removed. Commit: 5f886ea31fd89f42807ded1665e628459c846741.
- A push to the implementation branch did not create a GitHub Actions run. Direct repository Actions runs query returned total_count=0; combined status for the workflow commit returned no statuses. The connector exposes only GET for workflow/repository resources and has no workflow-dispatch or Actions-settings write operation. Therefore this session cannot enable Actions or dispatch a run. The owner must enable GitHub Actions in repository Settings → Actions → General (if disabled) or grant a connection with Actions write permission; after that, push/dispatch can be retried.
- The PR remains open and draft, base `awg-3.1-core`, head `5f886ea31fd89f42807ded1665e628459c846741`; no merge performed. No tests are reported as passed. Rust build, fmt, clippy, unit tests and live interop remain unverified.
- Static inspection confirms the newly added lifecycle tests exercise pending signature queue reconfiguration and forced retry. They remain unexecuted. The harness remains one direction (amneziawg-go client → BoringTun server) and ICMP only; reverse role and TCP/UDP are still TODO.


### 2026-11-02 — повторная проверка GitHub Actions

- Повторно проверен endpoint `/actions/runs?per_page=20`: GitHub вернул `total_count=0`, список запусков пуст. В PR #3 head остаётся `88dfb38abf39e710d99708f802238b28be2ffd2b`; PR открыт, draft, не объединён.
- Проверка состояния ветки подтверждает, что последний commit не изменился после предыдущей попытки. Следующий шаг — создать отдельный документационный commit в этой рабочей ветке, чтобы повторно проверить push-trigger. Это не заменяет ручной запуск и не является результатом тестов.



### 2026-11-02 — TCP/UDP transport coverage added to the interop harness

- Added `scripts/awg-traffic-check.py`, a standard-library-only echo probe launched inside the isolated server/client network namespaces.
- Extended `scripts/awg-go-interop.sh` to run the probe after the official amneziawg-go client completes its handshake and ICMP check.
- TCP sends 256 KiB, shuts down the write side, and verifies the complete echoed stream byte-for-byte. UDP sends a 1200-byte datagram and verifies the echoed payload byte-for-byte. Both request and response directions therefore cross the tunnel.
- The UDP size is chosen to fit the harness's 1420-byte tunnel MTU with the configured S4 prefix and WireGuard overhead.
- This adds coverage only; it is not a test result. The helper and namespace harness have **not** been executed in this environment. The cross-implementation role remains amneziawg-go client → BoringTun server; reverse-role testing is still outstanding.
- The I1–I5 protocol implementation is unchanged. Rust compilation, formatting, clippy, unit tests and live interop remain blocked pending an actual CI run.


- Local-only functional check: the Python helper was syntax-parsed and then run with its endpoint changed to loopback; it successfully echoed 262,144 TCP bytes and 1,200 UDP bytes byte-for-byte. This validates the helper's socket logic, **not** the tunnel or namespace harness.
- GitHub Actions was observed again after the branch update. The latest `PR Status Checks` run (`41439474240`) and Semgrep run (`41439472908`) both ended in `startup_failure`; the workflow-runs API reports no jobs for these runs. GitHub defines `startup_failure` as a check-suite startup failure, not a job-level test failure. No Rust or network test has started, so the protocol stage remains blocked.


### Header-protection integration map — static source review

The next Rust stage should be implemented around these confirmed call sites, rather than adding a detached cipher helper:

- Outbound packets of all four kinds converge on `Tunn::write_to_network`, which currently calls `AmneziaConfig::prepend_outbound`. This is the central point to add header masking **after** S-prefix bytes have been generated, so the first 12 prefix bytes can be used as the ChaCha20 nonce and the complete fixed/transport message (including handshake MACs) can be masked.
- Inbound packets enter `Tunn::decapsulate`, which currently calls `strip_inbound` before `RateLimiter::verify_packet` and packet parsing. Header unmasking must happen before `strip_inbound`, otherwise the masked H1-H4 type cannot be classified. The current `datagram: &[u8]` API is immutable; the implementation needs a bounded mutable scratch copy or a carefully redesigned receive buffer. Reusing `dst` is unsafe because the caller's tunnel-output buffer is not guaranteed to hold the full UDP datagram.
- The key belongs to interface-wide Amnezia configuration and must participate in the existing transactional UAPI merge. A non-zero key is valid only when all S1-S4 prefix lengths are at least 12 bytes; validate the merged tuple atomically, not one UAPI line at a time.
- The pinned Go sender creates a ChaCha20 stream using the first 12 S-prefix bytes as nonce, starts at the stream beginning, and XORs the complete Noise message after MAC generation. The receiver first recovers the masked message type from the first four keystream bytes, identifies the matching S/H pair, then continues the same stream over the remaining message bytes. A zero key disables masking.
- Tests must cover each of H1/H2/H3/H4, both zero and non-zero key, nonce changes, wrong S/H candidate, truncated prefixes, invalid key/S combinations, MAC verification after unmasking, and transport receiver-index/counter recovery. Cross-implementation packet captures are required before declaring parity.

This is a call-site and ordering map only. No header-protection code has been added, compiled or tested in this stage.


### Header-protection source review correction — exact masked byte ranges

A deeper read of the pinned `device/send.go` and `device/receive.go` corrects an overly broad phrase in the earlier integration map:

- Handshake initiation, response and cookie reply: after MAC generation, ChaCha20 XOR covers the complete fixed-size Noise message (from message type through MAC fields), excluding S-prefix and random trailer.
- Transport data: ChaCha20 XOR covers **only the 16-byte transport header** (type + receiver index + counter), not the AEAD ciphertext/content. The receiver first derives four keystream bytes to classify H4, then applies those four bytes to the type and consumes the next 12 stream bytes for receiver/counter. The encrypted payload remains untouched for normal AEAD verification.
- The cipher is initialized from the first 12 bytes of the S-prefix, uses the configured 32-byte key, and begins at stream position zero for each datagram.
- The previous wording that described the transport message as a whole being masked was imprecise; implementation and tests must use the packet-kind-specific ranges above.

Pinned references: `device/send.go`, `device/receive.go`, `device/noise-types.go`, tag `v3.1.20260828`.
