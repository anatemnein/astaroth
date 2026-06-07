import re

_IP = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_PORT_SVC = re.compile(r"\b(\d{1,5})/(tcp|udp)\s+open\s+(\S+)")
_NTLM_FULL = re.compile(r"\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b")
_HASH_NT = re.compile(r"\b([a-fA-F0-9]{32})\b")
_USER_DOMAIN = re.compile(r"([\w\-\.]+)\\([\w\-\.\$]+)")
_USER_AT = re.compile(r"([\w\-\.]+)@([\w\-\.]+\.\w+)")
_TICKET = re.compile(r"doIF[a-zA-Z0-9+/=]{60,}")


class GenericParser:
    name = "generic"

    def confidence(self, text: str) -> float:
        if _IP.search(text):
            return 0.3
        return 0.1

    def parse(self, text: str) -> dict:
        hosts: dict[str, dict] = {}
        credentials = []
        findings = []

        for m in _IP.finditer(text):
            ip = m.group(1)
            parts = list(map(int, ip.split(".")))
            if parts[0] in (0, 127, 255) or parts[3] == 255:
                continue
            if ip not in hosts:
                hosts[ip] = {"ip": ip, "hostname": "", "os": "", "services": []}

        for m in _PORT_SVC.finditer(text):
            port, proto, svc = int(m.group(1)), m.group(2), m.group(3)
            snippet = text[max(0, m.start() - 300): m.start()]
            ip_matches = list(_IP.finditer(snippet))
            if ip_matches:
                ip = ip_matches[-1].group(1)
                if ip in hosts:
                    existing = {s["port"] for s in hosts[ip]["services"]}
                    if port not in existing:
                        hosts[ip]["services"].append({
                            "port": port, "protocol": proto,
                            "service": svc, "version": "", "banner": "",
                        })

        seen_secrets = set()
        for m in _NTLM_FULL.finditer(text):
            secret = m.group(1)
            if secret in seen_secrets:
                continue
            seen_secrets.add(secret)
            snippet = text[max(0, m.start() - 150): m.start()]
            ud = _USER_DOMAIN.search(snippet) or _USER_AT.search(snippet)
            username = ud.group(2) if ud else "unknown"
            domain = ud.group(1) if ud else ""
            credentials.append({
                "username": username, "secret": secret,
                "secret_type": "ntlm", "domain": domain, "source": "generic",
            })

        for m in _TICKET.finditer(text):
            findings.append({
                "title": "Kerberos ticket (base64)",
                "description": "Base64-encoded Kerberos ticket found — import with Rubeus or impacket",
                "evidence": m.group(0)[:60] + "...",
                "severity": "high",
                "type": "kerberos",
                "host_ip": "",
            })

        return {
            "hosts": list(hosts.values()),
            "credentials": credentials,
            "findings": findings,
        }
