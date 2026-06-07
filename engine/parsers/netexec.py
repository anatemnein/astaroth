import re


class NetExecParser:
    name = "netexec"

    def confidence(self, text: str) -> float:
        if re.search(r"(SMB|LDAP|WINRM|MSSQL|SSH|RDP|WMI)\s+\d+\.\d+\.\d+\.\d+\s+\d+", text):
            return 0.95
        if re.search(r"crackmapexec|netexec|\bnxc\b|CrackMapExec", text, re.IGNORECASE):
            return 0.85
        return 0.0

    def parse(self, text: str) -> dict:
        hosts: dict[str, dict] = {}
        findings = []
        credentials = []

        for line in text.splitlines():
            m = re.match(
                r"\s*(SMB|LDAP|WINRM|MSSQL|SSH|FTP|RDP|WMI)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S*)\s+(.*)",
                line, re.IGNORECASE,
            )
            if not m:
                continue

            proto = m.group(1).upper()
            ip = m.group(2)
            port = int(m.group(3))
            hostname = m.group(4).strip("[]")
            message = m.group(5)

            if ip not in hosts:
                hosts[ip] = {"ip": ip, "hostname": hostname, "os": "", "services": []}
            host = hosts[ip]
            if hostname and not host["hostname"]:
                host["hostname"] = hostname

            existing_ports = {s["port"] for s in host["services"]}
            if port not in existing_ports:
                host["services"].append({
                    "port": port, "protocol": "tcp",
                    "service": proto.lower(), "version": "", "banner": "",
                })

            os_m = re.search(r"Windows [^\s]+ [^\s]+ Build \d+|Windows Server \d+[^\s]*", message)
            if os_m and not host["os"]:
                host["os"] = os_m.group(0).strip()

            # SMB signing
            if proto == "SMB" and re.search(r"signing:False|signing: False|SMBv1:False", message, re.IGNORECASE):
                if not any(f["host_ip"] == ip and "Signing" in f["title"] for f in findings):
                    findings.append({
                        "title": f"SMB Signing Disabled: {ip}",
                        "description": "SMB signing not enforced — host is susceptible to NTLM relay",
                        "evidence": line.strip(),
                        "severity": "high",
                        "type": "smb",
                        "host_ip": ip,
                    })

            # Successful authentication
            if re.search(r"\[\+\]", message):
                cred_m = re.search(r"([\w\-\.]+)\\([\w\-\.]+)[: ]+(\S+)", line)
                if cred_m:
                    credentials.append({
                        "username": cred_m.group(2),
                        "secret": cred_m.group(3),
                        "secret_type": "password",
                        "domain": cred_m.group(1),
                        "source": "netexec",
                    })

            # Admin / Pwn3d
            if re.search(r"Pwn3d!|Admin!", message, re.IGNORECASE):
                findings.append({
                    "title": f"Admin access: {ip}",
                    "description": f"Administrative access obtained via {proto}",
                    "evidence": line.strip(),
                    "severity": "critical",
                    "type": "auth",
                    "host_ip": ip,
                })

            # Shares
            for share_m in re.finditer(r"(ADMIN\$|C\$|IPC\$|[\w\-]+)\s+READ|WRITE", message):
                findings.append({
                    "title": f"Share accessible: {share_m.group(0).split()[0]} on {ip}",
                    "description": "Network share accessible with current credentials",
                    "evidence": line.strip(),
                    "severity": "medium",
                    "type": "smb",
                    "host_ip": ip,
                })

        return {
            "hosts": list(hosts.values()),
            "credentials": credentials,
            "findings": findings,
        }
