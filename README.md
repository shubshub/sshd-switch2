# sshd for Switch 2

An SSH and SFTP server for a Switch 2 running kaiHEN. It lets you copy files to and
from the SD card from your PC, and start homebrew from the command line. Login uses
SSH keys only; there are no passwords. It listens on port **2222**, because the
Switch doesn't let homebrew use ports below 1024.

## What you need

- A Switch 2 with kaiHEN and hbmenu working.
- A PC with OpenSSH: `ssh`, `scp`, `sftp`, `ssh-keygen`. Windows 10/11, macOS and
  Linux all include it.
- The console and the PC on the same network.

## Install

1. Get `sshd.nro`: build it (see `BUILDING.md`) or take it from this repository's
   Releases. Put it in `sd/switch/sshd/` next to the `authorized_keys` template, then
   copy the `switch` folder from `sd/` to the root of the SD card. You should end up
   with `sdmc:/switch/sshd/sshd.nro` and `sdmc:/switch/sshd/authorized_keys`.
2. On your PC, make a key if you don't have one:
   ```
   ssh-keygen -t ecdsa
   ```
3. Paste the whole contents of your public key file into
   `sdmc:/switch/sshd/authorized_keys`, as a new line under the comments. That's
   `~/.ssh/id_ed25519.pub`, or `C:\Users\<you>\.ssh\id_ed25519.pub` on Windows.
   - Use one key per line, as a plain `ssh-ed25519 AAAA… comment` line.
   - Lines with OpenSSH options in front (`from=`, `command=`, …) are refused.
   - Ed25519 is the tested key type. ECDSA and RSA keys should work too.

## Start it

Open hbmenu (under kaiHEN, hold **R** while starting a game) and run **sshd**. The
first start takes a few seconds while it creates the console's host key
(`ssh_host_ecdsa_key.der`, kept on the SD card). Then the screen shows:

```
Listening on <console IP>:2222
Host key SHA256:…
```

If it says `No sdmc:/switch/sshd/authorized_keys yet`, step 3 didn't take; nobody can
log in until it does. Press **+** on the controller to quit.

## Connect

```
ssh -p 2222 switch@<console IP>
```

Any user name works; only the key is checked. On the first connection, ssh shows the
host key's fingerprint: check it matches the one on the console's screen.

### Copying files

```
scp -P 2222 myfile.nro switch@<console IP>:/switch/myapp/myfile.nro
scp -P 2222 switch@<console IP>:/switch/myapp/log.txt .
sftp -P 2222 switch@<console IP>
```

Paths are SD card paths: `/switch/...` is `sdmc:/switch/...`.

### The built-in shell

`ssh` gives you a small shell, not a full one:

| command | does |
|---|---|
| `ls [dir]`, `cd [dir]`, `pwd` | browse the SD card |
| `cat <file>` | print a file |
| `mkdir <dir>`, `rmdir <dir>`, `rm <file>`, `mv <from> <to>` | manage files |
| `launch <nro> [arg]` | start that homebrew when the session closes; sshd exits |
| `help`, `exit` | |

You can also run one command without a session, for example
`ssh -p 2222 switch@<console IP> ls /switch`.

**`launch`** hands the console over to another NRO through the homebrew loader:
`launch /switch/myapp/myapp.nro`. sshd exits as soon as your session closes, and the
NRO starts. Run sshd from hbmenu again afterwards, or have your NRO start it when it
finishes.

## Good to know

- **scp may print `read remote "…" : End of file` after a download.** The file
  usually arrived complete; check its size or hash if it matters.
- **Up to 4 connections at once.**
- **It runs inside the game's process,** as all kaiHEN homebrew does. If the
  process crashes, kaiHEN takes you back to the menu.
- **Logs:** `sdmc:/switch/sshd/sshd.log` records each start-up step, and
  `lastload.txt` records how the last homebrew it launched ended.
- **Security:** anyone whose key is in `authorized_keys` can read, change and delete
  anything on the SD card. Keep that file to your own keys, and use it on a network
  you trust.

## Source and licence

GPL-3.0-or-later. It's built on wolfSSL 5.9.4 and wolfSSH 1.6.0, both GPLv3 (see
`LICENSE` and `licenses/`). This repository is the source of sshd itself and its build
files; see `BUILDING.md`.
