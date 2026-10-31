# basic mode: one line to turn a spare machine into an agent worker

The owner sends you an invite (it expires within one hour) and you run, in a Terminal window you are sitting at, on an
Apple-silicon Mac (macOS 14+) or an Ubuntu 24.04 / 26.04 x86_64 PC with `/dev/kvm`:

```
curl -fsSL https://raw.githubusercontent.com/mirrorstack-ai/fleet-disk/main/basic/install.sh | sh -s -- <invite>
```

`--host NAME` after the invite picks the machine's name (default: `mac-` or `pc-`, the machine's own name, and 4 hex of its id).

## What it does (8 steps, each safe to run again)

1. checks the invite's shape, the machine, free disk (Mac 45 GB, PC 10 GB) and RAM (PC 11 GB), and asks for sudo;
2. downloads the invite's encrypted asset, checks its sha256, decrypts it (the key goes to openssl's stdin only) and unpacks the
   fleet code into a root-owned folder (only `fleet/`, `bin/fleet-basic*.py` and `COMMIT`; anything else stops it);
3. Mac: installs the pinned python.org Python (sha256 and signature checked, framework only); PC: uses Ubuntu's `python3`;
4. installs `fleet-basic` with the switch OFF;
5. starts building the VM image in the background (a Mac stays awake meanwhile);
6. runs `claude setup-token` for your own Claude account and lets you paste the token into `fleet-basic` (never anywhere else);
7. prints a `PAIR` line: send it to the owner and read the owner the `ph=` characters of the next `WAIT` line out loud (a call, not the chat), it waits up to 60 minutes for the answer;
8. installs the image, runs doctor and mint-test, switches on, prints `FLEET-BASIC READY host=... runner=... claude=...`: send that line
   to the owner.

Install Claude Code first (`curl -fsSL https://claude.ai/install.sh | bash`, then open a new Terminal window) if it says `STOP claude`.
Any failure is one `STOP <code> <why>` line and a non-zero exit; send it to the owner. Run the line again (with a new invite when
the first one expired) and it resumes.

## What stays private

This script and this repository hold no secret and no private code. The fleet code is inside the encrypted invite, readable only by the
holder of that invite's key for under one hour. The runner App key reaches the machine encrypted to the key this machine made itself;
your Claude token never leaves it.

## Stop and uninstall

- Pause or stop: `sudo /usr/local/sbin/fleet-basic off` (a running job finishes) or `sudo /usr/local/sbin/fleet-basic disable`.
- Uninstall (the folder is the one step 2 printed): Mac `sudo sh "/Library/Application Support/fleet-basic-src/<commit>/fleet/basic/install-mac.sh" uninstall`,
  PC `sudo sh /usr/local/share/fleet-basic-src/<commit>/fleet/basic/uninstall-linux.sh`; then `sudo rm -rf` that `fleet-basic-src` folder.
  A Mac keeps the python.org Python.
- Then revoke what the machine held: revoke the Claude token in your own Claude account, and tell the owner so the runner App key is deleted.
