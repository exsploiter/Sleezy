"""
Comprehensive real-life test suite for sleezy.py  (run: python test_sleezy.py)

Strategy:
- Use --profile ctf-quick for most embeds (Argon2 time_cost=1, 16 MB) for speed.
- 40 sections, 100+ individual assertions.
- No external files needed; all fixtures built in a temp directory.
"""
from __future__ import annotations
import hashlib, json, os, subprocess, sys, tempfile, wave, zipfile

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
from array import array
from pathlib import Path
from typing import Optional
import numpy as np
from PIL import Image

HERE   = Path(__file__).parent
SLEEZY = HERE / "sleezy.py"
PASS_C = 0
FAIL_C = 0
ALL    = []          # (name, ok, detail)
FAST   = ["--profile", "ctf-quick"]   # low-cost KDF for speed


# -- helpers ------------------------------------------------------------------

def run(*args, env_extra=None, timeout=180):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(
        [sys.executable, str(SLEEZY), *args],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        env=env, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def check(name, cond, detail=""):
    global PASS_C, FAIL_C
    tag = "PASS" if cond else "FAIL"
    suffix = f"  [{detail.strip()[:100]}]" if (not cond and detail) else ""
    print(f"{tag}: {name}{suffix}")
    PASS_C += int(cond);  FAIL_C += int(not cond)
    ALL.append((name, cond, detail))


def mkpng(p, w=64, h=64):
    Image.fromarray(
        (np.random.rand(h, w, 3) * 255).astype("uint8"), "RGB"
    ).save(p)


def mkwav(p, nframes=16000, sampwidth=2, nch=1):
    with wave.open(str(p), "wb") as w:
        w.setnchannels(nch);  w.setsampwidth(sampwidth);  w.setframerate(8000)
        if sampwidth == 2:
            samp = array("h", [i % 30000 - 15000 for i in range(nframes * nch)])
        else:
            samp = array("B", [i % 256 for i in range(nframes * nch)])
        w.writeframes(samp.tobytes())


def mktxt(p, lines=3000):
    p.write_text(
        "\n".join(f"line {i}: The quick brown fox jumps over the lazy dog."
                  for i in range(lines)),
        encoding="utf-8")


def mkzip(p, entries):
    with zipfile.ZipFile(p, "w") as zf:
        for n, c in entries.items():
            zf.writestr(n, c)


def sha256f(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def section(t):
    print("\n" + "-"*65 + "\n  " + t + "\n" + "-"*65)


def do_embed(d, carrier, payload, out, method=None, pw="pw", extra=None):
    args = ["embed", "-c", str(d/carrier), "-p", str(d/payload),
            "-o", str(d/out), "--passphrase", pw, "--quiet", *FAST]
    if method: args += ["-m", method]
    if extra:  args += extra
    return run(*args)


def do_extract(d, stego, out, method=None, pw="pw", extra=None):
    args = ["extract", "-s", str(d/stego), "-o", str(d/out),
            "--passphrase", pw, "--quiet"]
    if method: args += ["-m", method]
    if extra:  args += extra
    return run(*args)


def rt(d, carrier, payload, out, ex, method, pw="pw", embed_extra=None):
    """Full round-trip; returns (ok, detail_string)."""
    rc1, _, se1 = do_embed(d, carrier, payload, out,
                           method=method, pw=pw, extra=embed_extra)
    if rc1 != 0:
        return False, f"embed rc={rc1}: {se1}"
    rc2, _, se2 = do_extract(d, out, ex, method=method, pw=pw)
    if rc2 != 0:
        return False, f"extract rc={rc2}: {se2}"
    orig = (d / payload).read_bytes()
    rec  = d / ex / payload
    if not rec.exists():
        return False, "extracted file missing"
    return rec.read_bytes() == orig, ""


# ===========================================================================
def main():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)

        # -- build fixtures --------------------------------------------------
        mkpng(d/"c64.png",  64,  64)
        mkpng(d/"c128.png", 128, 128)
        mkpng(d/"c512.png", 512, 512)
        mkpng(d/"tiny.png",   3,   3)
        mkwav(d/"c.wav")
        mkwav(d/"stereo.wav", nframes=44100, nch=2)
        mkwav(d/"tiny.wav",   nframes=100)
        mkwav(d/"c8bit.wav",  sampwidth=1)
        mktxt(d/"c.txt")
        mkzip(d/"c.zip",  {"readme.txt": "hello", "data.bin": "x"*100})
        mkzip(d/"c.docx", {"word/document.xml": "<w:document/>",
                            "[Content_Types].xml": "<Types/>"})
        (d/"c.bin").write_bytes(bytes(range(256)) * 32)
        (d/"mykey.bin").write_bytes(os.urandom(64))

        homo_cover = (
            "The steganography operations allow concealing vital messages "
            "inside ordinary text files without detection or awareness. "
            "Every piece of information must be protected carefully always. " * 200
        )
        (d/"homo.txt").write_text(homo_cover, encoding="utf-8")

        uni_cover = (
            "The observer sees that мир меняется. 行く川の流れは絶えずして。" * 100
        )
        (d/"unicover.txt").write_text(uni_cover, encoding="utf-8")

        # payloads
        (d/"secret.txt").write_text("CTF{sleezy_full_test_suite}", encoding="utf-8")
        (d/"empty.bin").write_bytes(b"")
        (d/"binary.bin").write_bytes(bytes(range(256)))
        (d/"unicode.txt").write_text("こんにちは世界 [LOCK] Привет мир", encoding="utf-8")
        (d/"big8k.bin").write_bytes(os.urandom(8192))
        (d/"big50k.bin").write_bytes(os.urandom(50000))
        (d/"big70k.bin").write_bytes(os.urandom(70000))

        (d/"multi").mkdir()
        (d/"multi"/"alpha.txt").write_text("ALPHA")
        (d/"multi"/"beta.txt").write_text("BETA")
        (d/"multi"/"gamma.bin").write_bytes(b"\xde\xad\xbe\xef" * 16)

        # -- 1. All 7 methods: basic round-trip ----------------------------
        section("1. All 7 methods -- basic round-trip (secret.txt)")
        for method, carrier, out, ex in [
            ("image.lsb",       "c64.png",  "rt_lsb.png",  "ex_lsb"),
            ("audio.lsb",       "c.wav",    "rt_wav.wav",  "ex_wav"),
            ("text.zero-width", "c.txt",    "rt_zw.txt",   "ex_zw"),
            ("text.whitespace", "c.txt",    "rt_ws.txt",   "ex_ws"),
            ("text.homoglyph",  "homo.txt", "rt_homo.txt", "ex_homo"),
            ("archive.comment", "c.zip",    "rt_zip.zip",  "ex_zip"),
            ("generic.append",  "c.bin",    "rt_app.bin",  "ex_app"),
        ]:
            ok, detail = rt(d, carrier, "secret.txt", out, ex, method)
            check(f"{method} round-trip", ok, detail)

        # -- 2. Empty payload ---------------------------------------------
        section("2. Empty payload (zero-byte file)")
        for method, carrier, out, ex in [
            ("image.lsb",      "c64.png", "e_lsb.png", "ex_e_lsb"),
            ("audio.lsb",      "c.wav",   "e_wav.wav", "ex_e_wav"),
            ("generic.append", "c.bin",   "e_app.bin", "ex_e_app"),
            ("archive.comment","c.zip",   "e_zip.zip", "ex_e_zip"),
        ]:
            ok, detail = rt(d, carrier, "empty.bin", out, ex, method)
            check(f"{method} round-trip (empty payload)", ok, detail)

        # -- 3. Binary payload (all byte values 0-255) ---------------------
        section("3. Binary payload (all byte values 0-255)")
        for method, carrier, out, ex in [
            ("image.lsb",      "c64.png", "b_lsb.png", "ex_b_lsb"),
            ("generic.append", "c.bin",   "b_app.bin", "ex_b_app"),
            ("archive.comment","c.zip",   "b_zip.zip", "ex_b_zip"),
        ]:
            ok, detail = rt(d, carrier, "binary.bin", out, ex, method)
            check(f"{method} round-trip (binary payload)", ok, detail)

        # -- 4. Unicode payload --------------------------------------------
        section("4. Unicode / multibyte payload")
        ok, detail = rt(d, "c64.png", "unicode.txt", "u_lsb.png", "ex_u_lsb", "image.lsb")
        check("image.lsb round-trip (unicode payload)", ok, detail)
        ok, detail = rt(d, "c.bin",   "unicode.txt", "u_app.bin", "ex_u_app", "generic.append")
        check("generic.append round-trip (unicode payload)", ok, detail)

        # -- 5. Multi-file tar bundle --------------------------------------
        section("5. Multi-file tar bundle")
        rc, _, se = run("embed", "-c", str(d/"c.bin"),
                        "-p", str(d/"multi"/"alpha.txt"),
                            str(d/"multi"/"beta.txt"),
                            str(d/"multi"/"gamma.bin"),
                        "-m", "generic.append", "--passphrase", "multi",
                        "-o", str(d/"multi_out.bin"), "--quiet", *FAST)
        rc2, _, se2 = run("extract", "-s", str(d/"multi_out.bin"),
                          "-m", "generic.append",
                          "-o", str(d/"ex_multi"),
                          "--passphrase", "multi", "--quiet")
        ok = (rc == 0 and rc2 == 0
              and (d/"ex_multi"/"alpha.txt").read_text() == "ALPHA"
              and (d/"ex_multi"/"beta.txt").read_text() == "BETA"
              and (d/"ex_multi"/"gamma.bin").read_bytes() == b"\xde\xad\xbe\xef"*16)
        check("multi-file tar bundle round-trip", ok, se or se2)

        # -- 6. --text (secret message) mode ------------------------------
        section("6. --text secret message mode")
        msg = "The eagle has landed at midnight."
        rc, _, se = run("embed", "-c", str(d/"c64.png"), "-t", msg,
                        "-o", str(d/"txt_msg.png"),
                        "--passphrase", "txtpw", "--quiet", *FAST)
        rc2, _, _ = run("extract", "-s", str(d/"txt_msg.png"),
                        "-o", str(d/"ex_txt_msg"),
                        "--passphrase", "txtpw", "--quiet")
        rec = d/"ex_txt_msg"/"payload.txt"
        ok = rc==0 and rc2==0 and rec.exists() and rec.read_text(encoding="utf-8")==msg
        check("--text mode round-trip (image.lsb)", ok, se)

        # -- 7. Wrong passphrase -> exit 5 ---------------------------------
        section("7. Wrong passphrase -> exit 5")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"auth.png"), "--passphrase", "correct",
            "--quiet", *FAST)
        for wrong in ["WRONG", "", "correc", "correct ", "Correct"]:
            rc, _, _ = run("extract", "-s", str(d/"auth.png"),
                           "-o", str(d/"ex_auth"),
                           "--passphrase", wrong, "--quiet")
            check(f"wrong passphrase {repr(wrong)} -> exit 5", rc == 5)

        # -- 8. Tampered carrier -------------------------------------------
        section("8. Tampered carrier")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"tamper_src.png"), "--passphrase", "tp",
            "--quiet", *FAST)

        arr = np.array(Image.open(d/"tamper_src.png").convert("RGB"))
        arr[0, 0, 0] ^= 1
        Image.fromarray(arr, "RGB").save(d/"tamper_magic.png")
        rc, _, _ = run("extract", "-s", str(d/"tamper_magic.png"),
                       "-m", "image.lsb", "-o", str(d/"ex_tm"),
                       "--passphrase", "tp", "--quiet")
        check("tampered magic bit -> exit 7", rc == 7)

        arr2 = np.array(Image.open(d/"tamper_src.png").convert("RGB"))
        arr2[5:30, :, :] ^= 1
        Image.fromarray(arr2, "RGB").save(d/"tamper_ct.png")
        rc, _, _ = run("extract", "-s", str(d/"tamper_ct.png"),
                       "-m", "image.lsb", "-o", str(d/"ex_tct"),
                       "--passphrase", "tp", "--quiet")
        check("tampered ciphertext -> exit 5 or 7", rc in (5, 7))

        run("embed", "-c", str(d/"c.bin"), "-p", str(d/"secret.txt"),
            "-m", "generic.append", "-o", str(d/"tapp.bin"),
            "--passphrase", "tp", "--quiet", *FAST)
        data = (d/"tapp.bin").read_bytes()
        (d/"tapp2.bin").write_bytes(data[:-10] + b"\x00"*10)
        rc, _, _ = run("extract", "-s", str(d/"tapp2.bin"),
                       "-m", "generic.append", "-o", str(d/"ex_tapp"),
                       "--passphrase", "tp", "--quiet")
        check("tampered EOF trailer -> non-zero exit", rc != 0)

        # -- 9. Oversized payload -> exit 3 --------------------------------
        section("9. Oversized payload -> exit 3")
        rc, _, _ = run("embed", "-c", str(d/"tiny.png"),
                       "-p", str(d/"secret.txt"),
                       "--passphrase", "x", "-o", str(d/"tiny_out.png"), *FAST)
        check("oversized in 3x3 PNG -> exit 3", rc == 3)

        rc, _, _ = run("embed", "-c", str(d/"tiny.wav"),
                       "-p", str(d/"binary.bin"),
                       "--passphrase", "x", "-o", str(d/"tiny_out.wav"), *FAST)
        check("oversized in tiny WAV -> exit 3", rc == 3)

        # -- 10. Dry-run ---------------------------------------------------
        section("10. Dry-run mode")
        dout = d/"dry.png"
        rc, _, _ = run("embed", "-c", str(d/"c64.png"),
                       "-p", str(d/"secret.txt"),
                       "--passphrase", "x", "--dry-run",
                       "-o", str(dout), *FAST)
        check("dry-run exits 0", rc == 0)
        check("dry-run writes no output file", not dout.exists())

        # -- 11. --auto detection ------------------------------------------
        section("11. Auto-detection (--auto)")
        for method, carrier, stego in [
            ("image.lsb",       "c64.png", "auto_lsb.png"),
            ("audio.lsb",       "c.wav",   "auto_wav.wav"),
            ("generic.append",  "c.bin",   "auto_app.bin"),
            ("archive.comment", "c.zip",   "auto_zip.zip"),
        ]:
            run("embed", "-c", str(d/carrier), "-p", str(d/"secret.txt"),
                "-m", method, "-o", str(d/stego),
                "--passphrase", "autopass", "--quiet", *FAST)
            ex = "ex_auto_" + method.replace(".", "_")
            rc, _, se = run("extract", "-s", str(d/stego),
                            "-o", str(d/ex), "--auto",
                            "--passphrase", "autopass", "--quiet")
            rec = d/ex/"secret.txt"
            ok = (rc == 0 and rec.exists()
                  and rec.read_text(encoding="utf-8") == "CTF{sleezy_full_test_suite}")
            check(f"--auto detects {method}", ok, se)

        # -- 12. Keyfile KDF mixing ----------------------------------------
        section("12. Keyfile KDF mixing")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"kf.png"), "--passphrase", "kwpass",
            "--keyfile", str(d/"mykey.bin"), "--quiet", *FAST)

        rc, _, _ = run("extract", "-s", str(d/"kf.png"),
                       "-o", str(d/"ex_kf_ok"), "--passphrase", "kwpass",
                       "--keyfile", str(d/"mykey.bin"), "--quiet")
        check("keyfile: correct pass + keyfile -> 0", rc == 0)

        rc, _, _ = run("extract", "-s", str(d/"kf.png"),
                       "-o", str(d/"ex_kf_nokey"),
                       "--passphrase", "kwpass", "--quiet")
        check("keyfile: missing keyfile -> exit 5", rc == 5)

        rc, _, _ = run("extract", "-s", str(d/"kf.png"),
                       "-o", str(d/"ex_kf_badpw"), "--passphrase", "WRONG",
                       "--keyfile", str(d/"mykey.bin"), "--quiet")
        check("keyfile: wrong pass + correct keyfile -> exit 5", rc == 5)

        # -- 13. Watermark ------------------------------------------------
        section("13. Watermark embedding")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"wm.png"), "--passphrase", "wmpass",
            "--watermark", "OWNER=alice;DATE=2024",
            "--quiet", *FAST)
        rc, out, _ = run("extract", "-s", str(d/"wm.png"),
                         "-o", str(d/"ex_wm"),
                         "--passphrase", "wmpass")
        check("watermark: extract exits 0", rc == 0)
        check("watermark: watermark in JSON output", "OWNER=alice" in out)

        # -- 14. Profile presets -------------------------------------------
        section("14. Profile presets")
        rc, out, _ = run("profile", "list")
        check("profile list exits 0", rc == 0)
        for pname in ("ctf-quick", "max-stealth", "max-capacity",
                      "watermark", "covert-text"):
            check(f"profile list has '{pname}'", pname in out)

        rc, out, _ = run("profile", "show", "ctf-quick")
        check("profile show ctf-quick exits 0", rc == 0)
        try:
            data = json.loads(out)
            check("profile show: valid JSON", True)
            check("ctf-quick cipher == aes-256-gcm",
                  data.get("cipher") == "aes-256-gcm")
        except Exception:
            check("profile show: valid JSON", False)
            check("ctf-quick cipher == aes-256-gcm", False)

        rc, _, _ = run("profile", "delete", "ctf-quick")
        check("cannot delete built-in profile -> exit 2", rc == 2)

        # -- 15. Steganalysis ---------------------------------------------
        section("15. Steganalysis (analyze)")
        for fname, label in [("c64.png","PNG"), ("c.wav","WAV"),
                              ("c.txt","TXT"), ("c.zip","ZIP"), ("c.bin","BIN")]:
            rc, out, _ = run("analyze", str(d/fname), "--json")
            check(f"analyze {label} exits 0", rc == 0)
            try:
                rep = json.loads(out)
                check(f"analyze {label}: suspicion_score in 0-100",
                      0 <= rep["suspicion_score"] <= 100)
            except Exception:
                check(f"analyze {label}: suspicion_score in 0-100", False)

        rc, out, _ = run("analyze", str(d/"c64.png"), "--json")
        try:
            rep = json.loads(out)
            check("PNG analysis: chi2_statistic present", "chi2_statistic" in rep)
            check("PNG analysis: lsb_one_ratio present",  "lsb_one_ratio" in rep)
        except Exception:
            check("PNG analysis: chi2_statistic present", False)
            check("PNG analysis: lsb_one_ratio present",  False)

        rc, out, _ = run("analyze", str(d/"c64.png"), "--bitplane", "--json")
        check("analyze --bitplane: bitplane_ascii in output",
              rc == 0 and "bitplane_ascii" in out)

        # Stego image analysis  -- should still work (no crash)
        rc, out, _ = run("analyze", str(d/"rt_lsb.png"), "--json")
        check("analyze of stego PNG exits 0", rc == 0)

        # -- 16. Methods & Formats -----------------------------------------
        section("16. Methods & Formats listing")
        rc, out, _ = run("methods", "--json")
        check("methods --json exits 0", rc == 0)
        try:
            items = json.loads(out)
            ids = [i["id"] for i in items]
            for mid in ("image.lsb", "audio.lsb", "text.zero-width",
                        "text.whitespace", "text.homoglyph",
                        "archive.comment", "generic.append"):
                check(f"methods includes {mid}", mid in ids)
        except Exception:
            check("methods --json valid", False)

        rc, out, _ = run("methods", "--family", "image", "--json")
        check("methods --family image excludes audio",
              rc == 0 and "audio" not in out)

        rc, out, _ = run("formats", "--json")
        check("formats --json exits 0", rc == 0)
        try:
            fams = json.loads(out)
            for fam in ("image", "audio", "text", "archive", "generic"):
                check(f"formats includes '{fam}'", fam in fams)
        except Exception:
            check("formats --json valid", False)

        # -- 17. Verify ----------------------------------------------------
        section("17. Verify (SHA-256 checksum)")
        rc, out, _ = run("verify", str(d/"secret.txt"))
        check("verify exits 0", rc == 0)
        h = out.strip().splitlines()[0].strip()
        check("verify: 64 hex chars",
              len(h) == 64 and all(c in "0123456789abcdef" for c in h))
        expected = sha256f(d/"secret.txt")
        check("verify sha256 correct", h.lower() == expected.lower())

        rc, out, _ = run("verify", str(d/"secret.txt"), "--hash", expected)
        check("verify --hash MATCH exits 0",  rc == 0 and "MATCH"    in out)

        rc, out, _ = run("verify", str(d/"secret.txt"), "--hash", "0"*64)
        check("verify --hash MISMATCH -> exit 1", rc == 1 and "MISMATCH" in out)

        # -- 18. Image LSB bits-per-channel 1-4 ---------------------------
        section("18. Image LSB bits-per-channel (1-4)")
        for bits in (1, 2, 3, 4):
            out_f = f"bits{bits}.png"
            ex_d  = f"ex_bits{bits}"
            do_embed(d, "c128.png", "secret.txt", out_f,
                     method="image.lsb", pw="bp",
                     extra=[f"--bits={bits}"])
            rc, _, se = do_extract(d, out_f, ex_d, method="image.lsb", pw="bp")
            rec = d/ex_d/"secret.txt"
            ok  = (rc == 0 and rec.exists()
                   and rec.read_text(encoding="utf-8") ==
                       "CTF{sleezy_full_test_suite}")
            check(f"image.lsb {bits}-bit round-trip", ok, se)

        # -- 19. AES-256-GCM cipher ----------------------------------------
        section("19. AES-256-GCM cipher")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "--cipher", "aes-256-gcm",
            "-o", str(d/"aes.png"),
            "--passphrase", "aespw", "--quiet", "--profile", "ctf-quick")
        rc, _, _ = run("extract", "-s", str(d/"aes.png"),
                       "-o", str(d/"ex_aes"),
                       "--passphrase", "aespw", "--quiet")
        check("AES-256-GCM round-trip",
              rc == 0 and (d/"ex_aes"/"secret.txt").exists())

        # -- 20. Compression variants --------------------------------------
        section("20. Compression variants (deflate, none)")
        for comp in ("deflate", "none"):
            run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
                f"--compress={comp}",
                "-o", str(d/f"comp_{comp}.png"),
                "--passphrase", f"cp{comp}", "--quiet",
                "--profile", "ctf-quick")
            rc, _, _ = run("extract", "-s", str(d/f"comp_{comp}.png"),
                           "-o", str(d/f"ex_comp_{comp}"),
                           "--passphrase", f"cp{comp}", "--quiet")
            check(f"--compress={comp} round-trip",
                  rc == 0 and (d/f"ex_comp_{comp}"/"secret.txt").exists())

        # -- 21. Bad/missing paths -----------------------------------------
        section("21. Error handling -- invalid paths")
        rc, _, _ = run("embed", "-c", "/nonexistent/x.png",
                       "-p", str(d/"secret.txt"),
                       "--passphrase", "x", "-o", str(d/"bad.png"))
        check("nonexistent carrier -> non-zero exit", rc != 0)

        rc, _, _ = run("embed", "-c", str(d/"c64.png"),
                       "-p", "/nonexistent/payload.txt",
                       "--passphrase", "x", "-o", str(d/"bad2.png"))
        check("nonexistent payload -> non-zero exit", rc != 0)

        rc, _, _ = run("extract", "-s", "/nonexistent/stego.png",
                       "-o", str(d/"bad_ex"), "--passphrase", "x")
        check("nonexistent stego -> non-zero exit", rc != 0)

        # -- 22. Archive.comment capacity limit ---------------------------
        section("22. Archive.comment capacity limit (65535 bytes)")
        rc, _, _ = run("embed", "-c", str(d/"c.zip"),
                       "-p", str(d/"big70k.bin"),
                       "-m", "archive.comment",
                       "--passphrase", "z", "-o", str(d/"zip_overflow.zip"),
                       *FAST)
        check("archive.comment: payload > 65535 -> exit 3", rc == 3)

        # -- 23. DOCX (ZIP-based) carrier ---------------------------------
        section("23. DOCX (ZIP-based) carrier via archive.comment")
        ok, detail = rt(d, "c.docx", "secret.txt",
                        "out.docx", "ex_docx", "archive.comment")
        check("archive.comment round-trip with .docx carrier", ok, detail)

        # -- 24. Unicode cover text ----------------------------------------
        section("24. Unicode cover text for text methods")
        ok, detail = rt(d, "unicover.txt", "secret.txt",
                        "uni_zw.txt", "ex_uni_zw", "text.zero-width")
        check("text.zero-width with Unicode cover", ok, detail)

        # -- 25. Stereo WAV carrier ----------------------------------------
        section("25. Stereo WAV (2-channel) carrier")
        ok, detail = rt(d, "stereo.wav", "secret.txt",
                        "stereo_out.wav", "ex_stereo", "audio.lsb")
        check("audio.lsb round-trip with stereo WAV", ok, detail)

        # -- 26. Special-character passphrases -----------------------------
        section("26. Special-character passphrases")
        for pw, label in [
            ("p@ssw0rd!#%^&*()", "special chars"),
            ("spaces in pass",   "spaces"),
            ("unicode_passphrase", "unicode label"),
            ("a",               "single char"),
        ]:
            run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
                "-o", str(d/"pwtest.png"),
                "--passphrase", pw, "--quiet", *FAST)
            rc, _, _ = run("extract", "-s", str(d/"pwtest.png"),
                           "-o", str(d/"ex_pw"),
                           "--passphrase", pw, "--quiet")
            ok = (rc == 0
                  and (d/"ex_pw"/"secret.txt").read_text() ==
                      "CTF{sleezy_full_test_suite}")
            check(f"passphrase: {label}", ok)

        # -- 27. Default output filename -----------------------------------
        section("27. Default output filename (no -o flag)")
        rc, _, _ = run("embed", "-c", str(d/"c64.png"),
                       "-p", str(d/"secret.txt"),
                       "--passphrase", "x", "--quiet",
                       "--profile", "ctf-quick")
        expected = d/"c64_stego.png"
        check("default output file created", expected.exists())
        if expected.exists():
            expected.unlink()

        # -- 28. Auto method selection by extension ------------------------
        section("28. Auto method selection by carrier extension")
        for carrier, pw in [("c64.png", "ae1"), ("c.wav", "ae2"), ("c.zip", "ae3")]:
            stem = carrier.replace(".", "_")
            outn = f"autoext_{stem}.{carrier.split('.',1)[1]}"
            run("embed", "-c", str(d/carrier), "-p", str(d/"secret.txt"),
                "-o", str(d/outn), "--passphrase", pw, "--quiet", *FAST)
            rc, _, _ = run("extract", "-s", str(d/outn),
                           "-o", str(d/f"ex_aext_{stem}"),
                           "--passphrase", pw, "--quiet")
            check(f"auto-method for .{carrier.split('.',1)[1]}", rc == 0)

        # -- 29. Missing payload argument -> exit 2 ------------------------
        section("29. Missing payload -> exit 2")
        rc, _, _ = run("embed", "-c", str(d/"c64.png"),
                       "--passphrase", "x", "-o", str(d/"noarg.png"))
        check("embed with no payload or --text -> exit 2", rc == 2)

        # -- 30. Unknown method -> exit 4 -----------------------------------
        section("30. Unknown method -> exit 4")
        rc, _, _ = run("embed", "-c", str(d/"c64.png"),
                       "-p", str(d/"secret.txt"),
                       "-m", "does.not.exist",
                       "--passphrase", "x", "-o", str(d/"badm.png"))
        check("embed with unknown method -> exit 4", rc == 4)

        # -- 31. Batch embed / extract -------------------------------------
        section("31. Batch embed / extract")
        bdir = d/"batch_c";  bdir.mkdir()
        bout = d/"batch_o";  bout.mkdir()
        for i in range(3):
            mkpng(bdir/f"b{i}.png", 64, 64)
        rc, _, se = run("batch", "embed",
                        "--glob", str(bdir/"*.png"),
                        "-p", str(d/"secret.txt"),
                        "--passphrase", "batchpw",
                        "-o", str(bout))
        check("batch embed exits 0", rc == 0, se)
        check("batch embed: 3 output files",
              len(list(bout.glob("*.png"))) == 3)
        bex = d/"batch_ex"
        rc, _, se = run("batch", "extract",
                        "--glob", str(bout/"*.png"),
                        "--passphrase", "batchpw",
                        "-o", str(bex))
        check("batch extract exits 0", rc == 0, se)

        # -- 32. Randomness -- two embeds differ ----------------------------
        section("32. Randomness: two embeds of same payload differ")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"rnd1.png"), "--passphrase", "r",
            "--quiet", *FAST)
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"rnd2.png"), "--passphrase", "r",
            "--quiet", *FAST)
        check("two embeds produce different outputs (random salt/nonce)",
              sha256f(d/"rnd1.png") != sha256f(d/"rnd2.png"))

        # -- 33. Cross-method extraction fails gracefully ------------------
        section("33. Cross-method extraction fails gracefully")
        run("embed", "-c", str(d/"c.bin"), "-p", str(d/"secret.txt"),
            "-m", "generic.append",
            "-o", str(d/"cross.bin"),
            "--passphrase", "cross", "--quiet", *FAST)
        rc, _, _ = run("extract", "-s", str(d/"cross.bin"),
                       "-m", "image.lsb",
                       "-o", str(d/"ex_cross"),
                       "--passphrase", "cross", "--quiet")
        check("extract with wrong method -> non-zero exit", rc != 0)

        # -- 34. Large carrier (512x512, 8 KB payload) ---------------------
        section("34. Large carrier (512x512 PNG, 8 KB binary payload)")
        ok, detail = rt(d, "c512.png", "big8k.bin",
                        "large_out.png", "ex_large", "image.lsb")
        check("image.lsb: 8 KB payload in 512x512 PNG", ok, detail)

        # -- 35. 8-bit WAV rejection ---------------------------------------
        section("35. 8-bit WAV rejection (only 16-bit PCM supported)")
        rc, _, _ = run("embed", "-c", str(d/"c8bit.wav"),
                       "-p", str(d/"secret.txt"),
                       "--passphrase", "x", "-o", str(d/"8bit_out.wav"),
                       *FAST)
        check("8-bit WAV -> non-zero exit", rc != 0)

        # -- 36. Non-ZIP as archive.comment --------------------------------
        section("36. Non-ZIP as archive.comment -> graceful error")
        rc, _, _ = run("embed", "-c", str(d/"c.bin"),
                       "-p", str(d/"secret.txt"),
                       "-m", "archive.comment",
                       "--passphrase", "x", "-o", str(d/"nz.bin"),
                       *FAST)
        check("non-ZIP archive.comment -> non-zero exit", rc != 0)

        # -- 37. Original carrier unchanged after embed --------------------
        section("37. Carrier integrity (original not modified)")
        orig = sha256f(d/"c64.png")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"integ.png"),
            "--passphrase", "x", "--quiet", *FAST)
        check("original carrier file unchanged", sha256f(d/"c64.png") == orig)

        # -- 38. Generic.append stacking -----------------------------------
        section("38. Generic append: stacking two payloads")
        run("embed", "-c", str(d/"c.bin"), "-p", str(d/"secret.txt"),
            "-m", "generic.append",
            "-o", str(d/"stack1.bin"),
            "--passphrase", "s1", "--quiet", *FAST)
        run("embed", "-c", str(d/"stack1.bin"), "-p", str(d/"binary.bin"),
            "-m", "generic.append",
            "-o", str(d/"stack2.bin"),
            "--passphrase", "s2", "--quiet", *FAST)
        rc, _, se = run("extract", "-s", str(d/"stack2.bin"),
                        "-m", "generic.append",
                        "-o", str(d/"ex_stack"),
                        "--passphrase", "s2", "--quiet")
        check("generic.append: second-layer embed extractable", rc == 0, se)

        # -- 39. SLEEZY_PASSPHRASE environment variable --------------------
        section("39. SLEEZY_PASSPHRASE environment variable")
        run("embed", "-c", str(d/"c64.png"), "-p", str(d/"secret.txt"),
            "-o", str(d/"env.png"),
            "--passphrase", "envpass", "--quiet", *FAST)
        rc, _, _ = run("extract", "-s", str(d/"env.png"),
                       "-o", str(d/"ex_env"), "--quiet",
                       env_extra={"SLEEZY_PASSPHRASE": "envpass"})
        check("SLEEZY_PASSPHRASE env var used for extraction", rc == 0)

        rc, _, _ = run("extract", "-s", str(d/"env.png"),
                       "-o", str(d/"ex_env_bad"), "--quiet",
                       env_extra={"SLEEZY_PASSPHRASE": "wrongenv"})
        check("wrong SLEEZY_PASSPHRASE env var -> exit 5", rc == 5)

        # -- 40. text.homoglyph with binary payload ------------------------
        section("40. text.homoglyph round-trip with binary payload")
        ok, detail = rt(d, "homo.txt", "binary.bin",
                        "homo_bin.txt", "ex_homo_bin", "text.homoglyph")
        check("text.homoglyph round-trip (binary payload)", ok, detail)

    # -- summary ----------------------------------------------------------
    total = PASS_C + FAIL_C
    print(f"\n{'='*65}")
    print(f"  RESULTS: {PASS_C}/{total} passed,  {FAIL_C} failed")
    print('='*65)
    if FAIL_C:
        print("\nFailed tests:")
        for name, ok, detail in ALL:
            if not ok:
                suffix = f"\n    detail: {detail.strip()[:120]}" if detail else ""
                print(f"  FAIL: {name}{suffix}")
    sys.exit(1 if FAIL_C else 0)


if __name__ == "__main__":
    main()
