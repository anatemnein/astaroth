import re
import xml.etree.ElementTree as ET


class NmapParser:
    name = "nmap"

    def confidence(self, text: str) -> float:
        if "<nmaprun" in text:
            return 1.0
        if re.search(r"Nmap scan report for|PORT\s+STATE\s+SERVICE", text):
            return 0.9
        if re.search(r"\d+/tcp\s+open\s+\S+", text):
            return 0.8
        return 0.0

    def parse(self, text: str) -> dict:
        if "<nmaprun" in text:
            return self._parse_xml(text)
        return self._parse_text(text)

    def _parse_xml(self, text: str) -> dict:
        hosts = []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return self._parse_text(text)

        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is not None and status.get("state") != "up":
                continue

            ip, hostname, os_guess = "", "", ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
            for hn in host_el.findall(".//hostname"):
                if hn.get("type") in ("PTR", "user") and not hostname:
                    hostname = hn.get("name", "")
            for osmatch in host_el.findall(".//osmatch"):
                os_guess = osmatch.get("name", "")
                break

            services = []
            for port in host_el.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                services.append({
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "version": f"{product} {version}".strip(),
                    "banner": svc.get("extrainfo", "") if svc is not None else "",
                })

            if ip:
                hosts.append({"ip": ip, "hostname": hostname, "os": os_guess, "services": services})

        return {"hosts": hosts, "credentials": [], "findings": []}

    def _parse_text(self, text: str) -> dict:
        hosts = []
        current: dict | None = None

        for line in text.splitlines():
            m = re.match(r"Nmap scan report for (.+)", line)
            if m:
                if current:
                    hosts.append(current)
                raw = m.group(1).strip()
                ip_m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", raw)
                if ip_m:
                    ip = ip_m.group(1)
                    hostname = raw.split("(")[0].strip()
                else:
                    ip_m2 = re.search(r"(\d+\.\d+\.\d+\.\d+)", raw)
                    ip = ip_m2.group(1) if ip_m2 else raw
                    hostname = ""
                current = {"ip": ip, "hostname": hostname, "os": "", "services": []}
                continue

            if current is None:
                continue

            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if m:
                current["services"].append({
                    "port": int(m.group(1)),
                    "protocol": m.group(2),
                    "service": m.group(3),
                    "version": m.group(4).strip(),
                    "banner": "",
                })

            m = re.search(r"OS details?: (.+)", line)
            if m and not current["os"]:
                current["os"] = m.group(1).strip()

        if current:
            hosts.append(current)

        return {"hosts": hosts, "credentials": [], "findings": []}
