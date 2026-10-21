# Sleezy: Product Requirements Document

**Version:** 1.0 (Draft) | **Owner:** Mikoo | **Status:** Ready for build planning

> **One-liner:** Sleezy is a modular steganography workbench. It hides any payload inside almost any carrier, with a real CLI engine underneath and a browser-based terminal GUI on top that anyone can use without coding knowledge.

---

## 1. Vision and Positioning

Existing steganography tools fall into two bad camps. Command-line tools (steghide, zsteg, OpenStego, outguess) are powerful but narrow, each handling one or two formats, with inconsistent flags. GUI tools are friendly but shallow, usually just LSB in PNG with a password box.

Sleezy sits in the gap:

- **One engine, many methods:** every carrier format and embedding algorithm is a plugin behind one consistent interface.
- **Two skins, one core:** a native CLI for power users and automation, and a web app that *feels* like a terminal but guides beginners with wizards, autocomplete and live previews.
- **Privacy by default:** all processing runs locally (in the browser via WebAssembly). Files never leave the user's machine.
- **Embed + Analyze:** hiding data is only half the job. Sleezy also measures capacity, detectability and integrity, and can run steganalysis on any file.

### 1.1 Target Users

| Persona | Needs | Sleezy answer |
| --- | --- | --- |
| **CTF player / student** | Quickly hide and extract flags, practise techniques | Guided mode, many methods, extract-and-detect |
| **Pentester / red-teamer** | Test DLP and detection, scriptable | Full CLI, JSON output, profiles, batch mode |
| **Privacy-conscious user / journalist** | Simple, safe, encrypted hiding | Wizard, strong crypto defaults, local-only |
| **Digital forensics analyst / researcher** | Detect and analyze stego | Analyzer module, reports, method fingerprinting |
| **Content creator / developer** | Invisible watermarks and provenance tags | Watermark mode, batch, API/library |

### 1.2 Responsible Use

Steganography is dual-use. Sleezy positions itself for privacy, CTFs, research, watermarking and defensive testing. The app ships with a short acceptable-use notice on first run, no telemetry, and no cloud processing. Out of scope: features designed to evade specific named security products or to deliver malware.

---

## 2. Goals and Non-Goals

### 2.1 Goals

1. Support embedding into 10+ carrier families at launch with multiple methods each.
2. Accept **any** file or text as payload (single file, multiple files, folders, raw text, stdin).
3. Provide a consistent, discoverable command grammar identical in CLI and web terminal.
4. Make the web GUI usable by a non-coder in under 2 minutes for a first successful embed.
5. Provide strong, correct cryptography with safe defaults and no user crypto decisions required.
6. Tell the user *before* embedding whether the payload fits and how detectable the result will be.
7. Be fully extensible: new carriers and methods are plugins.

### 2.2 Non-Goals (v1)

- No cloud storage, accounts, or server-side file processing.
- No network or protocol steganography (packet timing, DNS tunnels).
- No real-time video-stream steganography.
- No guarantee of undetectability against a well-funded adversary. Sleezy reports risk honestly rather than promising invisibility.

---

## 3. Core Concepts (Shared Vocabulary)

| Term | Meaning |
| --- | --- |
| **Carrier** | The cover file that hides data (image, audio, video, document, text, archive). |
| **Payload** | The secret data to hide (file, folder, text, stdin). |
| **Method** | An embedding algorithm bound to a carrier family (e.g. `png.lsb`, `jpeg.dct`, `wav.phase`). |
| **Stego object** | The output file containing the hidden payload. |
| **Pipeline** | Ordered stages a payload goes through: pack → compress → encrypt → ECC → scatter → embed. |
| **Profile** | A saved, named configuration of pipeline and method options (YAML). |
| **Vault** | A stego object containing one or more independent layers (see decoy mode). |
| **Analyzer** | The steganalysis engine that estimates capacity, detectability and finds hidden data. |

---

## 4. Functional Requirements

Priority key: **P0** = MVP, **P1** = v1.0, **P2** = post-launch.

### 4.1 Carrier and Method Support

| Carrier family | Formats | Methods | Priority |
| --- | --- | --- | --- |
| **Lossless image** | PNG, BMP, TIFF | `lsb` (1 to 4 bits per channel), `lsb-matching` (±1), `lsb-keyed` (PRNG-scattered), `bitplane` select, alpha-channel, palette-order | P0 |
| **Lossy image** | JPEG | `dct` coefficient embedding (F5-style with matrix encoding), `metadata` (EXIF/XMP/COM segments), `trailer` | P1 |
| **Palette image** | GIF | `palette-lsb`, `frame-delay`, `comment-block` | P1 |
| **Modern image** | WebP (lossless) | `lsb` | P2 |
| **Audio (PCM)** | WAV, FLAC | `lsb`, `phase-coding`, `echo-hiding`, `spread-spectrum` | P0 (lsb), P1 (rest) |
| **Audio (lossy)** | MP3 | `ancillary-bits`, `frame-padding`, `id3-frames` | P1 |
| **Video** | MP4, MKV, AVI | `container-atom` (custom boxes), `subtitle-track`, `frame-lsb` (lossless frames) | P2 |
| **Documents** | PDF | `object-stream`, `incremental-update`, `metadata`, `whitespace` | P1 |
| **Office / archives** | DOCX, XLSX, PPTX, ZIP | `zip-comment`, `custom-xml-part`, `slack-entry` | P1 |
| **Plain text** | TXT, MD, HTML, source code | `zero-width` Unicode, `whitespace` (trailing space/tab), `homoglyph`, `html-attribute-order` | P0 (zero-width, whitespace) |
| **Generic** | Any binary | `append` (EOF trailer), `polyglot` wrapper | P0 |

Each method declares its own metadata, consumed by the UI and the analyzer:

```
id, family, display_name, description,
capacity_fn(carrier, options) -> bytes,
robustness (none | recompress | resize | noise),
detectability_baseline (low | medium | high),
options_schema (typed, with defaults, min/max, help text)
```

### 4.2 Payload Handling

- **Inputs (P0):** a single file, raw text typed or pasted, stdin (CLI), drag-and-drop (web).
- **Inputs (P1):** multiple files and whole folders (auto-packed as a TAR stream), URL fetch for CLI only.
- **Pre-checks:** payload size, MIME sniffing, optional SHA-256 recorded inside the container for integrity.
- **Streaming:** payloads over 100 MB are processed in chunks so memory stays bounded.

### 4.3 The Pipeline (fully configurable)

Every stage is optional and individually configurable, but ships with safe defaults.

1. **Pack:** wraps payload(s) into a container with filename, MIME type, size, timestamps, checksum.
2. **Compress:** `zstd` (default), `deflate`, `brotli`, `none`. Auto-skips if payload is already compressed.
3. **Encrypt:** `XChaCha20-Poly1305` (default) or `AES-256-GCM`. Key derived from the passphrase using `Argon2id` with a per-file random salt. Keyfile support (P1). Authenticated encryption means tampering is detected.
4. **Error correction:** Reed-Solomon with a configurable redundancy percentage (P1). Essential for lossy or damaged carriers.
5. **Scatter:** a keyed PRNG (seeded from the key material) selects embedding positions so data is spread instead of sequential. Defeats naive sequential-LSB detectors (P0).
6. **Embed:** the chosen method writes bits into the carrier.
7. **Verify:** immediately re-extracts and compares the hash before the output file is written, so a corrupt result is never silently produced.

### 4.4 Capacity, Fit and Detectability Preview

Before embedding, Sleezy shows:

- **Capacity:** maximum bytes this carrier and method can hold, versus payload size after compression and ECC overhead.
- **Embedding rate:** percentage of carrier capacity used.
- **Detectability score (0 to 100):** estimated from method baseline, embedding rate, and carrier properties (noise level, texture).
- **Recommendations:** for example 'Payload uses 94% of capacity. Reduce to under 30% or choose a larger carrier to lower detection risk.'
- **Auto-select (`--auto`):** given a payload and a folder of carriers, ranks the best carrier and method combos.

### 4.5 Extraction

- Extract with passphrase and/or keyfile.
- **Auto-detect mode:** try known methods against the carrier and report which succeed (the header magic and authentication tag make false positives negligible).
- Restores original filenames and folder structure.
- Partial recovery report when ECC repaired errors.

### 4.6 Advanced Modes

- **Decoy / plausible deniability (P1):** two independent layers in one carrier, each with its own passphrase. Unlocking with the decoy passphrase reveals harmless content only. Unused space is filled with random data indistinguishable from ciphertext.
- **Multi-carrier split (P2):** split one payload across N carriers with k-of-n recovery (Shamir or erasure coding).
- **Watermark mode (P1):** embed short, robust IDs (owner, timestamp) with high ECC; includes a verify command.
- **Chaining (P2):** embed a stego object inside another carrier (nested layers).
- **Batch mode (P1):** embed or extract across directories using glob patterns and profiles, with a summary report.

### 4.7 Analyzer (Steganalysis)

Command: `sleezy analyze <file>`.

- Statistical tests: chi-square, RS analysis, sample-pair analysis, histogram anomalies (P1).
- Structural checks: data after EOF, odd metadata, unusual zip entries, zero-width characters, trailing whitespace patterns, JPEG quantization oddities (P0).
- LSB bit-plane viewer and entropy heatmap (web GUI) (P1).
- Side-by-side and diff-amplified view of carrier vs. stego image (P1).
- Exportable report (JSON, HTML, PDF) (P2).
- Output includes a confidence level and the honest caveat that results are probabilistic.

---

## 5. Interfaces

### 5.1 Unified Command Grammar

The same grammar works in the native CLI and in the web terminal.

```
sleezy <command> [subcommand] [arguments] [--options]

COMMANDS
  embed      Hide a payload inside a carrier
  extract    Recover a hidden payload
  analyze    Inspect a file for hidden data, estimate capacity
  methods    List / describe available methods
  formats    List supported carrier formats
  profile    Create, list, edit, export, import profiles
  batch      Run embed/extract over many files
  verify     Check integrity of a stego object or watermark
  wizard     Interactive guided mode
  config     Global settings
  help       Context-aware help
```

**Example invocations:**

```
sleezy embed -c cover.png -p secret.zip -m png.lsb --bits 2 --scatter \
       --encrypt xchacha20 --compress zstd --ecc 10 -o out.png

sleezy embed -c song.wav -t 'meet at 9' -m wav.phase --passphrase-prompt

sleezy extract -s out.png --auto -o ./recovered/

sleezy analyze suspicious.jpg --tests chi2,rs --report html

sleezy embed --profile ctf-quick -c img.png -p flag.txt

sleezy methods --family image --verbose
```

**Rules of the grammar:**

- Short and long flags for everything; every flag has a sensible default.
- Missing required inputs trigger an interactive prompt (never a cryptic error).
- `--json` on every command for machine-readable output; `--quiet` and `--verbose` levels.
- `--dry-run` shows exactly what would happen (capacity, detectability, pipeline) without writing files.
- Exit codes are documented and stable.
- Passphrases are never accepted as plain flags by default (shell-history leak). Use `--passphrase-prompt`, env var, or `--passphrase-file`. A `--passphrase` flag exists but prints a warning.

### 5.2 Web App: Terminal-Feel GUI

The web app is the signature feature. It must be a *real* terminal experience, not a form with a dark theme.

**Layout (desktop):**

- **Main pane:** an xterm.js-based terminal running the Sleezy command interpreter in the browser.
- **Right dock (collapsible):** live context panel showing the loaded carrier (preview, metadata, capacity gauge), the loaded payload, the detectability meter, and a pipeline diagram that highlights the current stage.
- **Top bar:** profile selector, theme switcher, 'new session', help.
- **Bottom status line:** active carrier, active method, memory usage, and a 'local-only, nothing uploaded' indicator.

**Terminal behaviors:**

| Feature | Detail |
| --- | --- |
| **Tab autocomplete** | Commands, flags, method IDs, and filenames in the virtual file system |
| **Inline hints** | Greyed-out ghost text shows the next expected argument |
| **Command history** | Up/down arrows, `Ctrl+R` reverse search, persisted per session |
| **Command palette** | `Ctrl+K` fuzzy-finds any command, profile or method and fills it in |
| **Drag-and-drop** | Dropping a file onto the terminal mounts it in the virtual FS and prints its path |
| **Virtual file system** | `ls`, `cd`, `cat` (safe preview), `rm`, `mv`, `download <file>` for session files |
| **Rich output** | Inline progress bars, tables, ASCII capacity gauges, and clickable image thumbnails |
| **Error UX** | Errors explain the cause and suggest a fix with a copy-ready corrected command |
| **Command echo** | Every GUI action also prints the equivalent CLI command so users learn by using it |

**Zero-code modes inside the same UI:**

1. **Wizard mode (`wizard` or a button):** a step-by-step flow (choose action → carrier → payload → method suggestion → options → confirm → run) rendered as terminal-styled prompts with arrow-key selection. At the end it shows the generated command.
2. **Form mode:** a toggle that swaps the terminal for a clean panel with the same options as fields. It generates the identical command underneath.
3. **Click-to-build:** clicking a method or option in the right dock inserts the corresponding flag into the command line.

This gives non-coders a path in, while power users never leave the keyboard.

**Mobile / tablet:** terminal view with an on-screen key bar (Tab, Ctrl, arrows), wizard mode as default, docks become bottom sheets.

### 5.3 Visual Design Direction

- Dark-first, monospace-heavy, subtle scanline or glow effects (toggleable, off for reduced-motion users).
- Themes: `sleezy-dark` (default), `matrix`, `amber-crt`, `paper-light`, `high-contrast`.
- A distinct ASCII logo banner on startup, with tips of the day.
- Colour semantics: green = success, amber = warning or detectability risk, red = error, cyan = informational.
- Accessible: WCAG AA contrast, screen-reader announcements for command results, full keyboard navigation, scalable font size.

---

## 6. Technical Architecture

### 6.1 Recommended Stack

| Layer | Choice | Reason |
| --- | --- | --- |
| **Core engine** | **Rust** library (`sleezy-core`) | Memory safety, performance, excellent crypto crates, compiles to WASM and native |
| **Native CLI** | Rust binary using `clap` | Single static binary for Linux, macOS, Windows |
| **Web engine** | `sleezy-core` compiled to **WebAssembly** (`wasm-bindgen`) running in a **Web Worker** | Local-only processing, UI never freezes |
| **Frontend** | React or Next.js + TypeScript + Tailwind | Fits your existing stack |
| **Terminal** | `xterm.js` + custom command interpreter (shared parser compiled from Rust) | Authentic terminal feel; identical grammar to the CLI |
| **State** | Zustand or similar, plus IndexedDB for profiles and history | Offline-capable |
| **Packaging** | PWA (installable, works offline), optional Tauri desktop wrapper later | Zero server cost |
| **Hosting** | Static hosting (Vercel, Netlify, Cloudflare Pages) | No backend needed |

*Alternative if you prefer staying in TypeScript/Python:* a TypeScript core (Node CLI + browser build) is faster to start but slower on large media and weaker for DCT and audio work. The Rust core is recommended because the same code powers both interfaces, which guarantees CLI and GUI behave identically.

### 6.2 Module Layout

```
sleezy/
├─ crates/
│  ├─ sleezy-core/        # pipeline, container format, crypto, ECC, PRNG scatter
│  ├─ sleezy-carriers/    # one module per format family (png, jpeg, wav, pdf, ...)
│  ├─ sleezy-methods/     # embedding algorithms, registered via trait
│  ├─ sleezy-analyzer/    # steganalysis tests and structural checks
│  ├─ sleezy-cli/         # native binary
│  └─ sleezy-wasm/        # WASM bindings
├─ web/                   # React/Next.js app, xterm.js terminal, docks, wizard
├─ profiles/              # built-in YAML profiles
├─ docs/                  # method guides, threat model, format spec
└─ tests/                 # fixtures, golden files, fuzz corpus
```

### 6.3 Plugin Interface (Rust trait, simplified)

```rust
trait EmbedMethod {
    fn id(&self) -> &'static str;
    fn family(&self) -> CarrierFamily;
    fn options_schema(&self) -> OptionsSchema;
    fn capacity(&self, carrier: &Carrier, opts: &Options) -> Result<usize>;
    fn embed(&self, carrier: &mut Carrier, bits: &mut BitSource, opts: &Options) -> Result<()>;
    fn extract(&self, carrier: &Carrier, opts: &Options) -> Result<BitSink>;
    fn detectability(&self, carrier: &Carrier, rate: f32) -> DetectScore;
}
```

New methods register themselves in a central registry; the UI, CLI help, autocomplete and wizard are all generated from `options_schema`, so adding a method requires zero UI code.

### 6.4 Container (Header) Format: `SLZY v1`

The hidden payload is wrapped in a self-describing, authenticated container so extraction can auto-detect and verify.

| Field | Size | Notes |
| --- | --- | --- |
| Magic | 4 B | Encrypted-in-place if encryption is on, so no recognizable signature leaks |
| Version | 1 B | Format version |
| Flags | 1 B | compressed, encrypted, ECC, multi-file, decoy-layer |
| KDF params | 12 B | Argon2id memory, iterations, parallelism |
| Salt | 16 B | Random per file |
| Nonce | 24 B | XChaCha20 nonce (or 12 B for AES-GCM) |
| Payload length | 8 B | Length after processing |
| ECC params | 4 B | Data/parity shards |
| Ciphertext | N | Compressed, packed payload |
| Auth tag | 16 B | Poly1305 / GCM tag covering header and body |

**Key design point:** with encryption enabled, the whole container (including the header) is indistinguishable from random bytes. Auto-detect works by trying decryption with the supplied key, not by scanning for a magic string.

### 6.5 Security Requirements

- Use only audited crypto libraries (`RustCrypto` family, `argon2`). No custom ciphers.
- Constant-time comparisons for tags; zeroize keys and passphrases from memory after use.
- Argon2id defaults: 64 MiB, 3 iterations, tuned lower on mobile with a clearly displayed warning.
- No telemetry, no analytics that include file data or filenames. Optional anonymous usage counters are opt-in only.
- Strict Content Security Policy, no third-party scripts at runtime, Subresource Integrity on assets, WASM bundle hash published.
- Fuzz all parsers (PNG, JPEG, WAV, PDF, ZIP) with `cargo-fuzz`, since carrier files are untrusted input.
- Memory and time limits per operation to prevent decompression bombs.
- Metadata hygiene: option to strip or randomize carrier metadata (EXIF, timestamps, software tags) so the output does not reveal the tool used.

### 6.6 Threat Model (documented in-app)

| Adversary | What Sleezy protects | What it does not |
| --- | --- | --- |
| Casual observer | Hidden content invisible to eye and ear | n/a |
| Automated steganalysis | Reduces risk through scatter, low embedding rate, LSB matching | No absolute guarantee |
| Someone with the file and no key | Content confidentiality via strong encryption | Existence of data may be suspected by statistics |
| Coerced disclosure | Decoy layer gives plausible deniability | Depends on adversary's knowledge of the tool |
| Recompression / resizing | ECC and robust methods (DCT, spread-spectrum) | LSB methods will not survive social-media recompression, and Sleezy warns about this |

---

## 7. Configuration and Profiles

Profiles are plain YAML, shareable, and importable. Built-in examples: `ctf-quick`, `max-stealth`, `max-capacity`, `watermark`, `social-media-safe`.

```yaml
name: max-stealth
description: Low embedding rate, scattered, encrypted, with ECC
carrier:
  prefer: [png, bmp]
  min_capacity_ratio: 4      # carrier must hold at least 4x the payload
method: png.lsb-matching
options:
  bits_per_channel: 1
  channels: [r, g, b]
  scatter: true
pipeline:
  compress: zstd
  encrypt: xchacha20
  kdf: { type: argon2id, memory_mib: 128, iterations: 4 }
  ecc: { type: reed-solomon, redundancy_pct: 10 }
output:
  strip_metadata: true
  verify_after_embed: true
  filename_template: '{carrier_stem}_{hash8}.{ext}'
```

Global config (`sleezy config`): default theme, default profile, output directory, memory limit, confirmation prompts, language.

---

## 8. User Flows

### 8.1 First-time non-coder (web, target: under 2 minutes)

1. Opens the app; the banner and a one-line prompt appear: *'New here? Type `wizard` or press Enter to start.'*
2. Enter launches the wizard. Choose **Hide something**.
3. Drops an image onto the terminal. The right dock shows its preview and capacity.
4. Types a message or drops a file as the payload. The dock shows the fit gauge.
5. Wizard recommends a method ('PNG LSB, scattered. Detectability: Low') and asks for a passphrase.
6. Review screen shows the generated CLI command. Confirm.
7. Progress bar, verification passes, **Download** button appears.

### 8.2 Power user (CLI)

`sleezy embed --profile max-stealth -c cover.png -p data.tar --passphrase-prompt -o out.png` → dry-run summary → embed → verified → done. Scriptable in CI with `--json`.

### 8.3 Analyst

Drops a suspicious file, runs `analyze`, reads the chi-square and structure findings, opens the bit-plane viewer, and exports a report. If a password is known or guessed, runs `extract --auto`.

---

## 9. Non-Functional Requirements

| Area | Requirement |
| --- | --- |
| **Performance** | Embed 1 MB payload into a 12 MP PNG in under 5 s in-browser on a mid-range laptop; native CLI at least 3x faster |
| **Memory** | Web: cap at 1 GB with a graceful error; stream large files |
| **File limits** | Web: up to 500 MB carrier (configurable); CLI: effectively unlimited |
| **Responsiveness** | UI never blocks (Web Workers); progress events at least every 200 ms for long jobs |
| **Reliability** | Round-trip integrity: 100% bit-exact extraction on all non-lossy paths; verified in CI |
| **Offline** | Fully functional offline after first load (PWA) |
| **Browsers** | Latest Chrome, Edge, Firefox, Safari (WASM + Workers); iOS Safari and Android Chrome for mobile |
| **Accessibility** | WCAG 2.2 AA, keyboard-only operation, reduced-motion support |
| **i18n** | English first; string tables ready for Hindi and Bengali |
| **Portability** | CLI binaries for Linux (x86\_64, aarch64), macOS (Intel, Apple Silicon), Windows |

---

## 10. Testing and Quality

- **Round-trip suite:** every method × every carrier fixture × random payload sizes (0 B, 1 B, 1 KB, near-capacity) must extract bit-exact.
- **Golden files:** frozen stego outputs verify the format never silently changes between versions.
- **Fuzzing:** carrier parsers and container parser, run nightly.
- **Steganalysis benchmark:** run Sleezy outputs against open-source detectors (`zsteg`, `StegExpose`, `stegdetect`) and track detection rates per method as a release metric.
- **Cross-interface parity test:** the same command in native CLI and WASM must produce byte-identical output given the same seed and inputs.
- **Usability testing:** 5 non-technical users complete the wizard flow unaided before v1.0.
- **Security review:** third-party or community audit of the crypto and container code before v1.0 release.

---

## 11. Roadmap

### Phase 0: Foundations (Weeks 1 to 2)

Repo, Rust workspace, CI, container format spec, crypto pipeline (compress → encrypt → pack), unit tests.

### Phase 1: MVP Engine (Weeks 3 to 6)

PNG/BMP LSB with scatter, WAV LSB, text zero-width and whitespace, generic append. Native CLI with `embed`, `extract`, `methods`, `analyze` (structural checks). Capacity calculator and verify step.

### Phase 2: Web Terminal (Weeks 7 to 10)

WASM build, Web Worker, xterm.js terminal with autocomplete, history, drag-and-drop, virtual file system, right dock with previews and capacity gauge, command echo.

### Phase 3: Guided UX (Weeks 11 to 12)

Wizard mode, form mode, click-to-build, themes, profiles, command palette, onboarding tour.

### Phase 4: Depth (Weeks 13 to 18)

JPEG DCT, GIF, MP3, PDF, DOCX/ZIP methods, ECC, keyfiles, batch mode, statistical steganalysis (chi-square, RS), bit-plane viewer, decoy layers.

### Phase 5: Hardening and Launch (Weeks 19 to 22)

Fuzzing, benchmark against detectors, security review, PWA polish, docs site, release binaries, demo video, public launch.

### Post-launch (P2)

Video carriers, multi-carrier split, chaining, report export, Tauri desktop app, plugin SDK for community methods, public method gallery.

---

## 12. Success Metrics

| Metric | Target |
| --- | --- |
| Time-to-first-successful-embed (new web user, wizard) | Under 2 minutes median |
| Round-trip success rate in CI | 100% on lossless paths |
| Carrier families supported at v1.0 | 8 or more |
| Wizard completion rate (beta testers) | Above 85% |
| Mean detectability (StegExpose) at 10% embedding rate, default profile | Below 10% flagged |
| GitHub stars or community adoption (6 months) | Stretch goal, 1,000+ |
| Critical security issues at release | 0 |

---

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Scope explosion (too many formats) | Delays | Strict P0/P1/P2 tiers; plugin architecture so formats ship independently |
| WASM performance on large media | Poor UX | Streaming, Workers, SIMD, and clear file-size guidance; native desktop path |
| Lossy-format methods are hard (JPEG DCT, MP3) | Quality or bugs | Start from published algorithms (F5, matrix encoding); extensive round-trip fuzzing |
| Users overtrust 'invisibility' | Harm from false security | Honest detectability scoring, threat model in-app, no absolute claims |
| Misuse concerns | Reputation | Acceptable-use notice, local-only design, no evasion-targeting features |
| Crypto implementation mistakes | Severe | Only audited libraries, external review, no custom primitives |
| Browser memory limits (mobile) | Crashes | Memory guards, lower Argon2 params with warnings, graceful errors |

---

## 14. Open Questions for You

1. **Core language:** commit to the Rust + WASM approach, or prefer a TypeScript-first build for speed of development?
2. **Licensing:** open source (MIT or Apache-2.0) for community growth, or source-available?
3. **Branding:** is 'Sleezy' final, and do you want the terminal persona to have a character voice (witty, minimal, or neutral)?
4. **MVP scope:** are PNG, WAV, text and generic append enough for the first public demo?
5. **Distribution:** web-only at first, or ship the native CLI binaries from day one?
6. **Integration:** should Sleezy connect with your other projects (for example, exposing analyzer findings to Sandframe or DebtRadar)?

---

## Appendix A: Command Reference (Draft)

| Command | Key options |
| --- | --- |
| `embed` | `-c/--carrier`, `-p/--payload`, `-t/--text`, `-m/--method`, `--bits`, `--channels`, `--scatter`, `--seed`, `--compress`, `--encrypt`, `--kdf`, `--ecc`, `--decoy`, `--strip-metadata`, `--profile`, `--auto`, `--dry-run`, `-o/--output` |
| `extract` | `-s/--stego`, `--auto`, `-m/--method`, `--passphrase-prompt`, `--keyfile`, `-o/--output-dir`, `--layer` |
| `analyze` | `<file>`, `--tests`, `--report`, `--bitplane`, `--deep` |
| `methods` | `--family`, `--verbose`, `--json` |
| `formats` | `--json` |
| `profile` | `list`, `show`, `new`, `edit`, `export`, `import`, `delete` |
| `batch` | `--glob`, `--profile`, `--jobs`, `--report` |
| `verify` | `<file>`, `--watermark`, `--hash` |
| `wizard` | `--mode embed\|extract\|analyze` |
| `config` | `get`, `set`, `reset` |

## Appendix B: Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Payload too large for carrier |
| 4 | Unsupported carrier or method |
| 5 | Authentication or decryption failed |
| 6 | Verification failed after embed |
| 7 | Nothing detected (extract --auto) |

## Appendix C: Suggested First Sprint Checklist

- [ ] Create Rust workspace and CI (fmt, clippy, tests)
- [ ] Write the container format spec and implement pack/unpack
- [ ] Implement Argon2id + XChaCha20-Poly1305 pipeline stage with tests
- [ ] Implement PNG LSB embed and extract with keyed scatter
- [ ] Build `sleezy embed` and `sleezy extract` for PNG
- [ ] Add capacity calculator and `--dry-run`
- [ ] Round-trip test harness with fixtures
- [ ] Set up WASM build and a hello-world Worker call
