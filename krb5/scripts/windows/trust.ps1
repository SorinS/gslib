# A two-way Kerberos realm trust between this domain and an MIT realm
# (A.TEST, the one scripts/kdc.py runs), with AES keys, and the account
# mit-alice that the realm's alice@A.TEST maps to (altSecurityIdentities),
# in GooseTesters: AD gives a mapped principal that account's PAC, an
# unmapped one none. The KDCs never talk to each other: a client carries
# the cross-realm TGT. AD refers nothing to an MIT realm (ksetup's
# host-to-realm map is the DC's own client's), so clients need
# [domain_realm] for the realm's hosts.
# The other side holds krbtgt/<REALM>@<DOMAIN> and krbtgt/<DOMAIN>@<REALM>
# made with the same password (scripts/ad.py adds them to its MIT realm).
# The password comes from C:\Goose\dc\trust.txt (one line), deleted once
# read. Run it again at any time: the trust is made anew.
param(
    [string]$Realm = 'A.TEST',
    [string]$MappedUser = 'alice'
)
$ErrorActionPreference = 'Stop'
$domain = (Get-ADDomain).DNSRoot
$plain = (Get-Content C:\Goose\dc\trust.txt -Raw).Trim()
Remove-Item C:\Goose\dc\trust.txt -Force

# netdom and ksetup through cmd: their output and the password stay out
# of the transcript, and PowerShell does not stop at their stderr.
function Quiet($line) {
    cmd /c "$line >NUL 2>&1"
    return $LASTEXITCODE
}
Quiet "netdom trust $domain /Domain:$Realm /remove /force" | Out-Null
$rc = Quiet "netdom trust $domain /Domain:$Realm /add /realm /twoway /PasswordT:$plain"
if ($rc -ne 0) { throw "netdom trust /add failed: $rc" }
$rc = Quiet "ksetup /setenctypeattr $Realm AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96"
if ($rc -ne 0) { throw "ksetup /setenctypeattr failed: $rc" }

# mit-alice: a random password nobody needs (only the mapping is used).
$base = (Get-ADDomain).DistinguishedName
$rand = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
if (-not (Get-ADUser -Filter "sAMAccountName -eq 'mit-alice'")) {
    New-ADUser -Name 'mit-alice' -SamAccountName 'mit-alice' -UserPrincipalName "mit-alice@$domain" `
        -AccountPassword $rand -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,$base"
}
Set-ADUser -Identity 'mit-alice' -Replace @{ altSecurityIdentities = "Kerberos:$MappedUser@$Realm"; 'msDS-SupportedEncryptionTypes' = 0x18 }
Add-ADGroupMember -Identity 'GooseTesters' -Members 'mit-alice'

Get-ADTrust -Filter "Name -eq '$Realm'" | Select-Object Name,Direction,TrustType,ForestTransitive | Format-List
ksetup /getenctypeattr $Realm
Get-ADUser -Identity 'mit-alice' -Properties altSecurityIdentities | Select-Object SamAccountName,altSecurityIdentities | Format-List
