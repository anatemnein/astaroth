import re

_ESC = {
    "ESC1":  ("critical", "Template allows SAN with low-privileged enrollment — direct impersonation"),
    "ESC2":  ("high",     "Any purpose / no EKU — flexible certificate abuse"),
    "ESC3":  ("high",     "Certificate Request Agent EKU — enroll on behalf of another user"),
    "ESC4":  ("high",     "Writable template ACL — attacker can reconfigure template"),
    "ESC5":  ("high",     "Writable PKI object ACL"),
    "ESC6":  ("critical", "EDITF_ATTRIBUTESUBJECTALTNAME2 on CA — SAN in any request"),
    "ESC7":  ("high",     "Vulnerable CA ACL"),
    "ESC8":  ("critical", "NTLM relay to AD CS HTTP enrollment endpoint"),
    "ESC9":  ("medium",   "No security extension — weak certificate mapping"),
    "ESC10": ("medium",   "Weak certificate mappings"),
    "ESC11": ("medium",   "IF_ENFORCEENCRYPTICERTREQUEST disabled"),
    "ESC13": ("high",     "OID group link abuse"),
}


class CertipyParser:
    name = "certipy"

    def confidence(self, text: str) -> float:
        if re.search(r"Certificate Authorities|Certificate Templates|certipy", text, re.IGNORECASE):
            return 0.95
        if re.search(r"\bESC[0-9]+\b", text):
            return 0.9
        return 0.0

    def parse(self, text: str) -> dict:
        hosts, findings, credentials = [], [], []

        # CA hosts
        for m in re.finditer(r"CA Name\s*:\s*(.+)", text):
            ca = m.group(1).strip()
            hosts.append({
                "ip": ca, "hostname": ca, "os": "Windows AD CS",
                "services": [{"port": 443, "protocol": "tcp", "service": "adcs", "version": "", "banner": ""}],
            })

        # Vulnerable templates
        blocks = re.split(r"\n\s*\n", text)
        for block in blocks:
            template_m = re.search(r"Template Name\s*:\s*(.+)", block)
            if not template_m:
                continue
            template = template_m.group(1).strip()
            for esc, (sev, desc) in _ESC.items():
                if re.search(rf"\b{esc}\b", block):
                    findings.append({
                        "title": f"{esc}: {template}",
                        "description": desc,
                        "evidence": f"Template: {template}",
                        "severity": sev,
                        "type": "adcs",
                        "host_ip": "",
                    })

        # Hashes from certipy auth
        for m in re.finditer(r"Got hash for '([^']+)': (\S+)", text):
            parts = m.group(1).split("@")
            username = parts[0]
            domain = parts[1] if len(parts) > 1 else ""
            credentials.append({
                "username": username,
                "secret": m.group(2),
                "secret_type": "ntlm",
                "domain": domain,
                "source": "certipy",
            })

        # TGT saved
        for m in re.finditer(r"Saved AS-REQ to '([^']+)'", text):
            findings.append({
                "title": "TGT obtained via PKINIT",
                "description": "Certificate authentication succeeded — TGT available",
                "evidence": f"Saved to: {m.group(1)}",
                "severity": "critical",
                "type": "adcs",
                "host_ip": "",
            })

        return {"hosts": hosts, "credentials": credentials, "findings": findings}
