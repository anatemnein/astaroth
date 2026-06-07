import json
import re


class BloodHoundParser:
    name = "bloodhound"

    def confidence(self, text: str) -> float:
        t = text.strip()
        if not (t.startswith("{") or t.startswith("[")):
            return 0.0
        try:
            data = json.loads(t)
        except json.JSONDecodeError:
            return 0.0
        # BloodHound JSON collections
        if isinstance(data, dict):
            keys = set(data.keys())
            if keys & {"meta", "data", "nodes", "edges"}:
                return 0.95
        if isinstance(data, list) and data:
            obj = data[0] if isinstance(data[0], dict) else {}
            if obj.get("ObjectType") or obj.get("Properties") or obj.get("Members"):
                return 0.9
        return 0.0

    def parse(self, text: str) -> dict:
        hosts, findings, credentials = [], [], []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"hosts": hosts, "credentials": credentials, "findings": findings}

        objects = data if isinstance(data, list) else data.get("data", [])

        kerberoastable, asrep, unconstrained, constrained, admin_count = [], [], [], [], []

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            props = obj.get("Properties", {})
            name = props.get("name", obj.get("Name", ""))
            obj_type = obj.get("ObjectType", obj.get("type", "")).lower()

            if not props.get("enabled", True):
                continue

            if props.get("hasspn") and obj_type == "user":
                kerberoastable.append(name)
            if props.get("dontreqpreauth"):
                asrep.append(name)
            if props.get("unconstraineddelegation"):
                unconstrained.append(name)
            if props.get("allowedtodelegate"):
                constrained.append(name)
            if props.get("admincount"):
                admin_count.append(name)

            if obj_type == "computer" and name:
                ip = props.get("ipaddress", "") or ""
                hostname = re.sub(r"\$?$", "", name.lower())
                hosts.append({
                    "ip": ip or hostname,
                    "hostname": hostname,
                    "os": props.get("operatingsystem", ""),
                    "services": [],
                })

        if kerberoastable:
            findings.append({
                "title": f"Kerberoastable accounts ({len(kerberoastable)})",
                "description": "SPNs set on user accounts — offline hash cracking via GetUserSPNs",
                "evidence": ", ".join(kerberoastable[:10]),
                "severity": "high",
                "type": "kerberos",
                "host_ip": "",
            })
        if asrep:
            findings.append({
                "title": f"ASREPRoastable accounts ({len(asrep)})",
                "description": "Pre-auth disabled — capture AS-REP without credentials, crack offline",
                "evidence": ", ".join(asrep[:10]),
                "severity": "high",
                "type": "kerberos",
                "host_ip": "",
            })
        if unconstrained:
            findings.append({
                "title": f"Unconstrained delegation ({len(unconstrained)})",
                "description": "TGT stored in memory — coerce DC auth via PrintSpooler/PetitPotam to capture TGT",
                "evidence": ", ".join(unconstrained[:10]),
                "severity": "critical",
                "type": "delegation",
                "host_ip": "",
            })
        if constrained:
            findings.append({
                "title": f"Constrained delegation ({len(constrained)})",
                "description": "Allowed-to-delegate list set — S4U2Self/S4U2Proxy abuse possible",
                "evidence": ", ".join(constrained[:10]),
                "severity": "high",
                "type": "delegation",
                "host_ip": "",
            })

        return {"hosts": hosts, "credentials": credentials, "findings": findings}
