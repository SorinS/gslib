// krb5oracle prints go-krb5's reading of PAC data in the text form that
// krb5's test/pac.goose prints, so scripts/gen_vectors.py can record what
// the oracle sees and the Goose test compare against it.
//
// Input: lines "name|hex" (test/vectors/pac.txt). Output: for each, a line
// "== name" and the fields decoded.
//
//	go run . -version
//	go run . < ../../test/vectors/pac.txt
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/rpc/mstypes"
)

const version = "krb5oracle 1 (go-krb5 7e3cb81)"

func ft(f mstypes.FileTime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

func sid(s mstypes.RPCSID) string {
	if s.SubAuthorityCount == 0 && s.Revision == 0 {
		return ""
	}
	return s.String()
}

func groups(g []mstypes.GroupMembership) string {
	var p []string
	for _, x := range g {
		p = append(p, fmt.Sprintf("%d:%d", x.RelativeID, x.Attributes))
	}
	return strings.Join(p, ",")
}

func sidAttrs(s []mstypes.KerbSidAndAttributes) string {
	var p []string
	for _, x := range s {
		p = append(p, fmt.Sprintf("%s:%d", sid(x.SID), x.Attributes))
	}
	return strings.Join(p, ",")
}

func dumpKVI(w *bufio.Writer, b []byte) {
	var k pac.KerbValidationInfo
	if err := k.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "kvi.error\n")
		return
	}
	fmt.Fprintf(w, "kvi.times=%d,%d,%d,%d,%d,%d\n", ft(k.LogOnTime), ft(k.LogOffTime), ft(k.KickOffTime),
		ft(k.PasswordLastSet), ft(k.PasswordCanChange), ft(k.PasswordMustChange))
	fmt.Fprintf(w, "kvi.names=%s|%s|%s|%s|%s|%s\n", k.EffectiveName.Value, k.FullName.Value, k.LogonScript.Value,
		k.ProfilePath.Value, k.HomeDirectory.Value, k.HomeDirectoryDrive.Value)
	fmt.Fprintf(w, "kvi.counts=%d,%d\n", k.LogonCount, k.BadPasswordCount)
	fmt.Fprintf(w, "kvi.ids=%d,%d\n", k.UserID, k.PrimaryGroupID)
	fmt.Fprintf(w, "kvi.groups=%s\n", groups(k.GroupIDs))
	fmt.Fprintf(w, "kvi.user_flags=%d\n", k.UserFlags)
	var key []byte
	for _, c := range k.UserSessionKey.CypherBlock {
		key = append(key, c.Data[:]...)
	}
	fmt.Fprintf(w, "kvi.session_key=%s\n", hex.EncodeToString(key))
	fmt.Fprintf(w, "kvi.server=%s|%s\n", k.LogonServer.Value, k.LogonDomainName.Value)
	fmt.Fprintf(w, "kvi.domain_id=%s\n", sid(k.LogonDomainID))
	fmt.Fprintf(w, "kvi.uac=%d,%d\n", k.UserAccountControl, k.SubAuthStatus)
	fmt.Fprintf(w, "kvi.ilogon=%d,%d,%d\n", ft(k.LastSuccessfulILogon), ft(k.LastFailedILogon), k.FailedILogonCount)
	fmt.Fprintf(w, "kvi.extra_sids=%s\n", sidAttrs(k.ExtraSIDs))
	fmt.Fprintf(w, "kvi.resource=%s|%s\n", sid(k.ResourceGroupDomainSID), groups(k.ResourceGroupIDs))
}

func dumpClientInfo(w *bufio.Writer, b []byte) {
	var k pac.ClientInfo
	if err := k.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "client_info.error\n")
		return
	}
	fmt.Fprintf(w, "client_info=%d|%s\n", ft(k.ClientID), k.Name)
}

func dumpUPN(w *bufio.Writer, b []byte) {
	var k pac.UPNDNSInfo
	if err := k.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "upn.error\n")
		return
	}
	fmt.Fprintf(w, "upn=%s|%s|%d\n", k.UPN, k.DNSDomain, k.Flags)
}

func dumpSig(w *bufio.Writer, name string, b []byte) {
	var k pac.SignatureData
	if _, err := k.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "%s.error\n", name)
		return
	}
	fmt.Fprintf(w, "%s=%d|%s|%d\n", name, int32(k.SignatureType), hex.EncodeToString(k.Signature), k.RODCIdentifier)
}

func dumpS4U(w *bufio.Writer, b []byte) {
	var k pac.S4UDelegationInfo
	if err := k.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "s4u.error\n")
		return
	}
	var t []string
	for _, s := range k.S4UTransitedServices {
		t = append(t, s.Value)
	}
	fmt.Fprintf(w, "s4u=%s|%s\n", k.S4U2proxyTarget.Value, strings.Join(t, ","))
}

func dumpDevice(w *bufio.Writer, b []byte) {
	var k pac.DeviceInfo
	if err := k.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "device.error\n")
		return
	}
	var d []string
	for _, g := range k.DomainGroup {
		d = append(d, sid(g.DomainID)+"="+groups(g.GroupIDs))
	}
	fmt.Fprintf(w, "device=%d,%d|%s|%s|%s|%s\n", k.UserID, k.PrimaryGroupID, sid(k.AccountDomainID), groups(k.AccountGroupIDs),
		sidAttrs(k.ExtraSIDs), strings.Join(d, ";"))
}

func dumpPAC(w *bufio.Writer, b []byte) {
	var p pac.PACType
	if err := p.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "pac.error\n")
		return
	}
	fmt.Fprintf(w, "pac.buffers=%d\n", p.CBuffers)
	for _, buf := range p.Buffers {
		fmt.Fprintf(w, "buffer=%d,%d,%d\n", buf.ULType, buf.CBBufferSize, buf.Offset)
		d := b[buf.Offset : buf.Offset+uint64(buf.CBBufferSize)]
		switch buf.ULType {
		case 1:
			dumpKVI(w, d)
		case 6:
			dumpSig(w, "server_sig", d)
		case 7:
			dumpSig(w, "kdc_sig", d)
		case 10:
			dumpClientInfo(w, d)
		case 11:
			dumpS4U(w, d)
		case 12:
			dumpUPN(w, d)
		case 14:
			dumpDevice(w, d)
		}
	}
}

func dumpAD(w *bufio.Writer, b []byte) {
	var a types.AuthorizationData
	if err := a.Unmarshal(b); err != nil {
		fmt.Fprintf(w, "ad.error\n")
		return
	}
	for _, e := range a {
		if e.ADType == 128 {
			dumpPAC(w, e.ADData)
			continue
		}
		if e.ADType != 1 {
			continue
		}
		var inner types.AuthorizationData
		if err := inner.Unmarshal(e.ADData); err != nil {
			fmt.Fprintf(w, "ad.error\n")
			return
		}
		for _, x := range inner {
			if x.ADType == 128 {
				dumpPAC(w, x.ADData)
			}
		}
	}
}

func main() {
	v := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *v {
		fmt.Println(version)
		return
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for in.Scan() {
		line := in.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, hx, ok := strings.Cut(line, "|")
		if !ok {
			fmt.Fprintln(os.Stderr, "krb5oracle: a line without '|'")
			os.Exit(1)
		}
		b, err := hex.DecodeString(hx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "krb5oracle: bad hex for", name)
			os.Exit(1)
		}
		fmt.Fprintf(w, "== %s\n", name)
		switch {
		case strings.HasPrefix(name, "MarshaledPAC_AuthorizationData"):
			dumpAD(w, b)
		case name == "MarshaledPAC_AD_WIN2K_PAC":
			dumpPAC(w, b)
		case strings.HasPrefix(name, "MarshaledPAC_Kerb_Validation_Info"):
			dumpKVI(w, b)
		case name == "MarshaledPAC_Client_Info":
			dumpClientInfo(w, b)
		case name == "MarshaledPAC_UPN_DNS_Info":
			dumpUPN(w, b)
		case name == "MarshaledPAC_Server_Signature":
			dumpSig(w, "server_sig", b)
		case name == "MarshaledPAC_KDC_Signature":
			dumpSig(w, "kdc_sig", b)
		}
	}
}
