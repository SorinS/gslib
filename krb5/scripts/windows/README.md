# Windows: an AD domain controller for the krb5 tests

PowerShell for turning a Windows Server test host into the DC of its own
forest (`goose.test`, NetBIOS `GOOSE` by default), with AD's ports closed
from outside. The host is public with no other firewall; the KDC (88),
LDAP (389) and DNS are reached only through ssh tunnels to its 127.0.0.1
(`ssh -L 8888:127.0.0.1:88 ...`).

The scripts go in `C:\Goose\scripts` on the host; `C:\Goose\dc` holds
only what they make or read once (logs, password files, the keytab).
Run them as Administrator over ssh, in this order:

1. `state.ps1`: DNS, interfaces, the inbound rules that admit ssh, what
   listens. Read-only; run it before and after.
2. `firewall.ps1`: inbound block rules for AD's TCP and UDP ports, then
   the AD DS role (no reboot needed).
3. `schedule.ps1 [-Domain goose.test] [-NetBios GOOSE]`, after copying
   the DSRM password to `C:\Goose\dc_p.txt` (one line, 0600 on the way): runs `promote.ps1` as SYSTEM, which creates the
   forest and reboots. Its log is `C:\Goose\dc\promote.log`; the password
   file is deleted once read and the task unregisters itself.

After the reboot, `state.ps1` again: sshd still admitted, AD's ports
listening but blocked inbound. Then:

4. `setup.ps1`, after copying the test users' password to
   `C:\Goose\dc\users.txt` (deleted once read): users alice (AES) and bob
   (AES and RC4) in the group GooseTesters; the service account svc-web
   with SPNs `HTTP/web.goose.test` and `host/web.goose.test`, AES only, and
   its keytab `C:\Goose\dc\web.keytab` from ktpass; the KDC's claims
   support on, a `department` claim type, alice's department set. Run it
   again at any time.

`krb5.conf` is the client side for the tunnels: the KDC as
`tcp/127.0.0.1:8888` (ssh forwards TCP only), `web.goose.test` resolved
locally (an `/etc/hosts` entry to 127.0.0.1 with a tunnel to the service,
or the name only, for tickets).

