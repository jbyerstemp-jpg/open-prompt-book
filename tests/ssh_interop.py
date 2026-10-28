"""Cross-check opb's SSH signatures against OpenSSH's own ssh-keygen.

Runs in CI (GitHub runners ship ssh-keygen). Locally it is skipped when
ssh-keygen is missing, unless OPB_REQUIRE_SSH=1 is set.

Checks, in both directions:
  1. opb can load a key made by ssh-keygen (what members actually use).
  2. ssh-keygen -Y verify accepts a signature made by opb.
  3. opb accepts a signature made by ssh-keygen -Y sign.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import opb  # noqa: E402

NS = "openpromptbook-v1"


def main() -> int:
    if not shutil.which("ssh-keygen"):
        if os.environ.get("OPB_REQUIRE_SSH") == "1":
            print("FAIL: ssh-keygen not found")
            return 1
        print("SKIPPED: ssh-keygen not installed")
        return 0
    tmp = Path(tempfile.mkdtemp())
    key = tmp / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "interop", "-f", str(key)], check=True)
    private = opb.load_private_key(str(key))
    public = opb.load_public_key_file(str(key) + ".pub")
    assert opb.public_of(private).fingerprint == public.fingerprint
    fp_line = subprocess.run(["ssh-keygen", "-l", "-f", str(key) + ".pub"], check=True,
                             capture_output=True, text=True).stdout.split()[1]
    assert fp_line == public.fingerprint, (fp_line, public.fingerprint)

    message = opb.pae(opb.PAYLOAD_TYPE, b'{"hello":"book"}')
    (tmp / "message.bin").write_bytes(message)
    (tmp / "allowed").write_text(f'tester namespaces="{NS}" {public.line()}\n')

    # opb signs, OpenSSH verifies
    (tmp / "opb.sig").write_text(opb.sshsig_armor(opb.sshsig_sign(private, message, NS)))
    with open(tmp / "message.bin", "rb") as fh:
        subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(tmp / "allowed"), "-I", "tester",
                        "-n", NS, "-s", str(tmp / "opb.sig")], stdin=fh, check=True)

    # OpenSSH signs, opb verifies
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", NS, str(tmp / "message.bin")], check=True)
    armored = (tmp / "message.bin.sig").read_text().strip().splitlines()
    blob = opb.b64d("".join(armored[1:-1]))
    signer = opb.sshsig_verify(blob, message, NS)
    assert signer.fingerprint == public.fingerprint

    # a wrong namespace must fail in OpenSSH too
    with open(tmp / "message.bin", "rb") as fh:
        bad = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(tmp / "allowed"), "-I", "tester",
                              "-n", "git", "-s", str(tmp / "opb.sig")], stdin=fh, capture_output=True)
    assert bad.returncode != 0
    shutil.rmtree(tmp)
    print("OK: opb and OpenSSH agree on keys, fingerprints and signatures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
