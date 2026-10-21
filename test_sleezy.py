"""
Round-trip + edge-case tests for sleezy.py. Run with: python3 test_sleezy.py
Builds its own fixtures in a temp dir; no external files needed.
"""
import struct
import subprocess
import sys
import tempfile
import wave
from array import array
from pathlib import Path

import numpy as np
from PIL import Image

HERE = Path(__file__).parent
SLEEZY = HERE / "sleezy.py"
PASS = 0
FAIL = 0


def run(*args):
    r = subprocess.run([sys.executable, str(SLEEZY), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout, r.stderr


def check(name, cond):
    global PASS, FAIL
    print(f"{'PASS' if cond else 'FAIL'}: {name}")
    PASS += int(cond)
    FAIL += int(not cond)


def main():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # fixtures
        Image.fromarray((np.random.rand(48, 48, 3) * 255).astype("uint8"), "RGB").save(d / "c.png")
        with wave.open(str(d / "c.wav"), "wb") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
            samples = array("h", [i % 30000 - 15000 for i in range(3000)])
            w.writeframes(samples.tobytes())
        (d / "c.txt").write_text("\n".join(f"line {i} filler text for whitespace slots" for i in range(3000)))
        (d / "c.bin").write_bytes(bytes(range(256)) * 8)
        (d / "secret.txt").write_text("CTF{sleezy_rt}")
        (d / "zero.bin").write_bytes(b"")

        cases = [
            ("image.lsb", "c.png", "out.png"),
            ("audio.lsb", "c.wav", "out.wav"),
            ("text.zero-width", "c.txt", "out_zw.txt"),
            ("text.whitespace", "c.txt", "out_ws.txt"),
            ("generic.append", "c.bin", "out.bin"),
        ]
        for method, carrier, outname in cases:
            for payload in ("secret.txt", "zero.bin"):
                rc, *_ = run("embed", "-c", str(d / carrier), "-p", str(d / payload),
                             "-m", method, "--passphrase", "pw123", "-o", str(d / outname), "--quiet")
                rc2, *_ = run("extract", "-s", str(d / outname), "-m", method,
                              "-o", str(d / "ex"), "--passphrase", "pw123", "--quiet")
                ok = rc == 0 and rc2 == 0 and (d / "ex" / payload).read_bytes() == (d / payload).read_bytes()
                check(f"{method} round-trip ({payload})", ok)

        # wrong passphrase -> exit 5
        rc, _, err = run("extract", "-s", str(d / "out.png"), "-m", "image.lsb",
                          "-o", str(d / "ex_wrong"), "--passphrase", "WRONG", "--quiet")
        check("wrong passphrase -> exit 5", rc == 5)

        # auto-detect (fresh embed, since 'out.wav' above was last overwritten by the zero.bin case)
        run("embed", "-c", str(d / "c.wav"), "-p", str(d / "secret.txt"), "-m", "audio.lsb",
            "--passphrase", "pw123", "-o", str(d / "out_auto.wav"), "--quiet")
        rc, _, _ = run("extract", "-s", str(d / "out_auto.wav"), "-o", str(d / "ex_auto"),
                       "--auto", "--passphrase", "pw123", "--quiet")
        check("--auto detection succeeds", rc == 0 and (d / "ex_auto" / "secret.txt").exists())

        # dry-run writes nothing
        out = d / "dry.png"
        rc, _, _ = run("embed", "-c", str(d / "c.png"), "-p", str(d / "secret.txt"),
                       "--passphrase", "x", "--dry-run", "-o", str(out))
        check("dry-run leaves no output file", rc == 0 and not out.exists())

        # oversized payload -> exit 3
        tiny = d / "tiny.png"
        Image.fromarray((np.random.rand(3, 3, 3) * 255).astype("uint8"), "RGB").save(tiny)
        rc, _, _ = run("embed", "-c", str(tiny), "-p", str(d / "secret.txt"),
                       "--passphrase", "x", "-o", str(d / "tiny_out.png"))
        check("oversized payload -> exit 3", rc == 3)

        # multi-file folder -> tar, via generic.append (ample capacity)
        (d / "pd").mkdir()
        (d / "pd" / "a.txt").write_text("A")
        (d / "pd" / "b.txt").write_text("B")
        rc, _, _ = run("embed", "-c", str(d / "c.bin"), "-p", str(d / "pd" / "a.txt"), str(d / "pd" / "b.txt"),
                       "-m", "generic.append", "--passphrase", "multi", "-o", str(d / "out_multi.bin"), "--quiet")
        rc2, _, _ = run("extract", "-s", str(d / "out_multi.bin"), "-m", "generic.append",
                        "-o", str(d / "ex_multi"), "--passphrase", "multi", "--quiet")
        ok = (rc == 0 and rc2 == 0 and (d / "ex_multi" / "a.txt").read_text() == "A"
              and (d / "ex_multi" / "b.txt").read_text() == "B")
        check("multi-file folder payload (tar)", ok)

        # tamper -> header magic broken -> exit 7
        arr = np.array(Image.open(d / "out.png").convert("RGB"))
        arr[0, 0, 0] ^= 1
        Image.fromarray(arr, "RGB").save(d / "tampered.png")
        rc, _, _ = run("extract", "-s", str(d / "tampered.png"), "-m", "image.lsb",
                       "-o", str(d / "ex_t"), "--passphrase", "pw123", "--quiet")
        check("tampered header -> exit 7 (nothing detected)", rc == 7)

        # analyze / methods / formats / verify smoke tests
        rc, out, _ = run("methods", "--json")
        check("methods --json runs", rc == 0 and "image.lsb" in out)
        rc, out, _ = run("analyze", str(d / "c.png"))
        check("analyze runs on image", rc == 0 and "suspicion_score" in out)
        rc, out, _ = run("verify", str(d / "secret.txt"))
        check("verify prints sha256", rc == 0 and len(out.strip().splitlines()[0]) == 64)

        # homoglyph method round-trip
        (d / "homo_cover.txt").write_text("The secret operations of steganography allow concealing vital messages inside ordinary text files without detection. " * 80)
        rc, _, _ = run("embed", "-c", str(d / "homo_cover.txt"), "-p", str(d / "secret.txt"),
                       "-m", "text.homoglyph", "--passphrase", "pw123", "-o", str(d / "out_homo.txt"), "--quiet")
        rc2, _, _ = run("extract", "-s", str(d / "out_homo.txt"), "-m", "text.homoglyph",
                        "-o", str(d / "ex_homo"), "--passphrase", "pw123", "--quiet")
        check("text.homoglyph round-trip", rc == 0 and rc2 == 0 and (d / "ex_homo" / "secret.txt").read_text() == "CTF{sleezy_rt}")

        # archive.comment (ZIP) method round-trip
        import zipfile
        with zipfile.ZipFile(d / "cover.zip", "w") as zf:
            zf.writestr("test.txt", "ordinary content inside zip")
        rc, _, _ = run("embed", "-c", str(d / "cover.zip"), "-p", str(d / "secret.txt"),
                       "-m", "archive.comment", "--passphrase", "pw123", "-o", str(d / "out_zip.zip"), "--quiet")
        rc2, _, _ = run("extract", "-s", str(d / "out_zip.zip"), "-m", "archive.comment",
                        "-o", str(d / "ex_zip"), "--passphrase", "pw123", "--quiet")
        check("archive.comment round-trip", rc == 0 and rc2 == 0 and (d / "ex_zip" / "secret.txt").read_text() == "CTF{sleezy_rt}")

        # profile list smoke test
        rc, out, _ = run("profile", "list")
        check("profile list runs", rc == 0 and "ctf-quick" in out)

        # analyze --bitplane
        rc, out, _ = run("analyze", str(d / "c.png"), "--bitplane", "--json")
        check("analyze --bitplane includes bitplane_ascii", rc == 0 and "bitplane_ascii" in out)

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
