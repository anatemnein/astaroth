import re
import json


class ADParser:
    """Handles ldapsearch, kerbrute, secretsdump, enum4linux, rpcclient output."""
    name = "ad"

    def confidence(self, text: str) -> float:
        if re.search(r"secretsdump|Dumping (local SAM|Domain Credentials|LSA Secrets|NTDS)", text, re.IGNORECASE):
            return 0.97
        if re.search(r"kerbrute|Valid user|VALID USERNAME|Password spray|AS-REP", text, re.IGNORECASE):
            return 0.92
        if re.search(r"^dn:\s|objectClass:\s|sAMAccountName:|ldapsearch|ldapdomaindump", text, re.IGNORECASE | re.MULTILINE):
            return 0.92
        if re.search(r"enum4linux|rpcclient|Domain Name:|Domain SID:|Local users", text, re.IGNORECASE):
            return 0.85
        if re.search(r"Administrator:500:|Guest:501:|krbtgt:", text):
            return 0.95
        return 0.0

    def parse(self, text: str) -> dict:
        hosts, credentials, findings = [], [], []

        # --- secretsdump ---
        if re.search(r"secretsdump|Dumping|SAM hashes|NTDS", text, re.IGNORECASE):
            credentials += self._parse_secretsdump(text)
            if credentials:
                findings.append({
                    "title": f"Domain credentials dumped ({len(credentials)} hashes)",
                    "description": "NTDS or SAM hashes obtained — domain/local compromise",
                    "evidence": f"First entry: {credentials[0]['username']}",
                    "severity": "critical",
                    "type": "credentials-dump",
                    "host_ip": "",
                })

        # --- kerbrute ---
        for m in re.finditer(r"VALID USERNAME:\s+(\S+)|Valid user found:\s*(\S+)", text, re.IGNORECASE):
            user = (m.group(1) or m.group(2)).strip()
            findings.append({
                "title": f"Valid AD user: {user}",
                "description": "Username confirmed valid in Active Directory",
                "evidence": m.group(0).strip(),
                "severity": "info",
                "type": "ad-enum",
                "host_ip": "",
            })
        for m in re.finditer(r"VALID LOGIN:\s+(\S+):(\S+)", text, re.IGNORECASE):
            parts = m.group(1).split("\\")
            username = parts[-1]
            domain = parts[0] if len(parts) > 1 else ""
            credentials.append({
                "username": username, "secret": m.group(2),
                "secret_type": "password", "domain": domain, "source": "kerbrute",
            })

        # --- ldapsearch / ldapdomaindump ---
        if re.search(r"^dn:\s|sAMAccountName:", text, re.IGNORECASE | re.MULTILINE):
            findings += self._parse_ldap(text)

        # --- enum4linux ---
        if re.search(r"enum4linux|Domain Name:|Domain SID:", text, re.IGNORECASE):
            findings += self._parse_enum4linux(text)
            for m in re.finditer(r"Domain Name:\s*(\S+)", text, re.IGNORECASE):
                hosts.append({
                    "ip": m.group(1).strip(), "hostname": m.group(1).strip(),
                    "os": "Windows Domain Controller", "services": [],
                })

        # --- rpcclient enumeration ---
        for m in re.finditer(r"user:\[([^\]]+)\] rid:\[([^\]]+)\]", text):
            findings.append({
                "title": f"AD user enumerated: {m.group(1)}",
                "description": "User account identified via RPC",
                "evidence": m.group(0),
                "severity": "info",
                "type": "ad-enum",
                "host_ip": "",
            })

        # --- ACL / BloodHound text output ---
        for m in re.finditer(
            r"(GenericAll|WriteDACL|WriteOwner|GenericWrite|ForceChangePassword|AllExtendedRights)"
            r".*?([\w\-\.]+\\[\w\-\.]+|[\w\-\.]+@[\w\-\.]+)",
            text, re.IGNORECASE,
        ):
            perm = m.group(1)
            principal = m.group(2)
            findings.append({
                "title": f"Dangerous ACL: {perm} for {principal}",
                "description": f"AD object permission {perm} held by {principal} — potential privilege escalation",
                "evidence": m.group(0)[:200],
                "severity": "high",
                "type": "ad-acl",
                "host_ip": "",
            })

        # --- LAPS ---
        if re.search(r"ms-MCS-AdmPwd|LAPS.*password|Local Admin Password", text, re.IGNORECASE):
            for m in re.finditer(r"ms-MCS-AdmPwd:\s*(\S+)", text, re.IGNORECASE):
                findings.append({
                    "title": "LAPS password readable",
                    "description": "Local administrator password visible via LAPS attribute",
                    "evidence": "ms-MCS-AdmPwd attribute found",
                    "severity": "critical",
                    "type": "credentials",
                    "host_ip": "",
                })

        # --- Domain trusts ---
        for m in re.finditer(r"Trust Partner:\s*(\S+)|trustedDomain:\s*(\S+)", text, re.IGNORECASE):
            domain = (m.group(1) or m.group(2)).strip()
            findings.append({
                "title": f"Domain trust found: {domain}",
                "description": "Cross-domain or cross-forest trust — evaluate for SID history / ExtraSID attacks",
                "evidence": m.group(0).strip(),
                "severity": "medium",
                "type": "ad-trust",
                "host_ip": "",
            })

        return {"hosts": hosts, "credentials": credentials, "findings": findings}

    def _parse_secretsdump(self, text: str) -> list[dict]:
        creds = []
        # Format: DOMAIN\username:RID:LM:NT:::
        for m in re.finditer(
            r"([\w\.\-]+)\\([\w\.\-\$]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::",
            text,
        ):
            creds.append({
                "username": m.group(2),
                "secret": f"{m.group(4)}:{m.group(5)}",
                "secret_type": "ntlm",
                "domain": m.group(1),
                "source": "secretsdump",
            })
        # Cleartext from LSA secrets
        for m in re.finditer(r"([\w\.\-]+)\s*:\s*(.{8,})\s*$", text, re.MULTILINE):
            val = m.group(2).strip()
            if not re.match(r"^[a-fA-F0-9:]{32,}$", val) and len(val) < 128:
                if re.search(r"[A-Z][a-z]|[!@#$%]|\d", val):
                    creds.append({
                        "username": m.group(1).strip(),
                        "secret": val,
                        "secret_type": "cleartext",
                        "domain": "",
                        "source": "secretsdump-lsa",
                    })
        # AES keys
        for m in re.finditer(
            r"([\w\.\-]+)\s+aes256-cts-hmac-sha1-96\s*:\s*([a-fA-F0-9]{64})",
            text, re.IGNORECASE,
        ):
            creds.append({
                "username": m.group(1).strip(),
                "secret": m.group(2),
                "secret_type": "aes256",
                "domain": "",
                "source": "secretsdump",
            })
        return creds

    def _parse_ldap(self, text: str) -> list[dict]:
        findings = []
        # AdminCount=1 users
        admin_users = re.findall(r"sAMAccountName:\s*(\S+)(?:.|\n)*?adminCount:\s*1", text, re.IGNORECASE)
        if admin_users:
            findings.append({
                "title": f"AdminCount=1 users ({len(admin_users)})",
                "description": "Users with AdminCount=1 are protected by AdminSDHolder — changes to their ACLs revert hourly",
                "evidence": ", ".join(admin_users[:10]),
                "severity": "medium",
                "type": "ad-enum",
                "host_ip": "",
            })
        # Password not required
        for m in re.finditer(r"sAMAccountName:\s*(\S+)(?:.|\n)*?userAccountControl:\s*(\d+)", text, re.IGNORECASE):
            uac = int(m.group(2))
            if uac & 0x20:  # PASSWD_NOTREQD
                findings.append({
                    "title": f"Password not required: {m.group(1)}",
                    "description": "PASSWD_NOTREQD flag set — account may have blank password",
                    "evidence": f"UAC: {uac}",
                    "severity": "high",
                    "type": "ad-enum",
                    "host_ip": "",
                })
        return findings

    def _parse_enum4linux(self, text: str) -> list[dict]:
        findings = []
        # Password policy
        m = re.search(r"Minimum password length:\s*(\d+)", text, re.IGNORECASE)
        if m and int(m.group(1)) < 8:
            findings.append({
                "title": f"Weak password policy: min length {m.group(1)}",
                "description": "Short minimum password length increases cracking success",
                "evidence": m.group(0),
                "severity": "medium",
                "type": "ad-policy",
                "host_ip": "",
            })
        # Null session
        if re.search(r"null session|anonymous.*allowed|got session", text, re.IGNORECASE):
            findings.append({
                "title": "Null/anonymous session allowed",
                "description": "Unauthenticated SMB/RPC access — enumerate users, shares, policies without credentials",
                "evidence": "Null session established",
                "severity": "high",
                "type": "smb",
                "host_ip": "",
            })
        return findings
