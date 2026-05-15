#!/usr/bin/env python3

import os
import re
import json
import hashlib
from pathlib import Path

# =========================
# PATHS
# =========================

BRAIN = Path.home() / "astaroth" / "brain"
SOURCES = BRAIN / "sources"
NODES = BRAIN / "graph" / "nodes"

NODES.mkdir(parents=True, exist_ok=True)

# =========================
# FOCUS AREAS
# =========================

FOCUS_PATHS = [
    "windows-hardening",
    "linux-hardening",
    "network-services-pentesting",
    "pentesting-web",
    "cloud",
    "kubernetes",
    "docker",
    "active-directory",
    "ad-certificates",
    "kerberos",
    "ntlm",
]

# =========================
# TOOL DETECTION
# =========================

TOOL_WORDS = [
    "certipy",
    "bloodhound",
    "impacket",
    "netexec",
    "crackmapexec",
    "nmap",
    "masscan",
    "rustscan",
    "ldapsearch",
    "rpcclient",
    "smbclient",
    "evil-winrm",
    "kerbrute",
    "rubeus",
    "mimikatz",
    "linpeas",
    "winpeas",
    "pspy",
    "docker",
    "kubectl",
    "helm",
    "aws",
    "az",
    "gcloud",
    "ffuf",
    "gobuster",
    "nuclei",
    "burp",
    "sqlmap",
    "wpscan",
    "nikto",
]

# =========================
# DOMAIN DETECTION
# =========================

DOMAIN_HINTS = {
    "active_directory": [
        "active directory",
        "domain controller",
        "domain admin",
        "ldap",
        "kerberos",
        "ntlm",
        "bloodhound",
        "delegation",
        "gpo",
        "writedacl",
        "writeowner",
        "genericall",
        "dcsync",
        "adcs",
        "certificate template",
        "certipy",
        "esc1",
        "esc2",
        "esc3",
        "esc4",
        "esc5",
        "esc6",
        "esc7",
        "esc8",
        "kerberoasting",
        "asreproast",
    ],

    "windows_infra": [
        "windows",
        "powershell",
        "winrm",
        "rdp",
        "uac",
        "registry",
        "service control manager",
        "seimpersonate",
        "ntds.dit",
        "lsass",
        "sam database",
        "dpapi",
        "wmi",
    ],

    "linux_infra": [
        "linux",
        "sudo",
        "suid",
        "capabilities",
        "cron",
        "systemd",
        "nfs",
        "pam",
        "shadow file",
        "/etc/passwd",
        "kernel exploit",
    ],

    "aws": [
        "arn:aws",
        "iam role",
        "iam policy",
        "s3 bucket",
        "sts assume-role",
        "lambda function",
        "ec2 instance",
        "cloudtrail",
        "secrets manager",
        "ecr",
        "ecs",
        "eks",
        "rds",
        "kms",
    ],

    "azure": [
        "azure",
        "entra",
        "azure ad",
        "graph api",
        "managed identity",
        "key vault",
        "storage account",
        "app registration",
        "service principal",
        "tenant id",
    ],

    "gcp": [
        "gcp",
        "google cloud",
        "service account",
        "compute engine",
        "cloud storage",
        "gke",
        "cloud run",
        "cloud functions",
    ],

    "containers": [
        "docker",
        "kubernetes",
        "k8s",
        "containerd",
        "runc",
        "clusterrole",
        "serviceaccount",
        "kubelet",
        "etcd",
        "privileged container",
    ],

    "network_services": [
        "ftp",
        "ssh",
        "snmp",
        "ldap",
        "smb",
        "rpc",
        "winrm",
        "rdp",
        "mssql",
        "postgres",
        "mysql",
        "redis",
        "vnc",
        "telnet",
        "dns",
    ],

    "web": [
        "xss",
        "cross-site scripting",
        "sqli",
        "sql injection",
        "csrf",
        "ssrf",
        "idor",
        "lfi",
        "rfi",
        "file upload",
        "jwt",
        "cors",
        "websocket",
        "react",
        "dom xss",
        "twig",
        "_fragment",
        "deserialization",
        "ssti",
    ],
}

# =========================
# PRIMITIVES
# =========================

PRIMITIVE_MAP = {

    "WriteDACL": [
        "writedacl",
        "write dacl",
    ],

    "WriteOwner": [
        "writeowner",
        "write owner",
    ],

    "GenericAll": [
        "genericall",
        "generic all",
    ],

    "GenericWrite": [
        "genericwrite",
        "generic write",
    ],

    "SeImpersonatePrivilege": [
        "seimpersonate",
    ],

    "DCSync": [
        "dcsync",
    ],

    "Kerberoasting": [
        "kerberoasting",
    ],

    "ASREPRoast": [
        "asreproast",
        "as-rep",
    ],

    "Delegation Abuse": [
        "delegation",
    ],

    "Certificate Abuse": [
        "adcs",
        "certificate template",
        "esc1",
        "esc2",
        "esc3",
        "esc4",
        "esc5",
        "esc6",
        "esc7",
        "esc8",
    ],

    "Secret Disclosure": [
        "secret disclosure",
        "app_secret",
        "api key",
        "password leak",
        ".env",
    ],

    "RCE": [
        "rce",
        "remote code execution",
        "code execution",
    ],

    "Deserialization": [
        "deserialization",
        "deserialize",
    ],

    "Template Injection": [
        "template injection",
        "twig",
        "ssti",
    ],

    "DACL Abuse": [
        "dacl",
        "acl abuse",
    ],

    "Token Impersonation": [
        "token impersonation",
        "impersonate",
    ],

    "SUID Abuse": [
        "suid",
    ],

    "sudo Abuse": [
        "sudo",
    ],

    "Writable Service": [
        "writable service",
        "service binary",
        "service permissions",
    ],

    "Metadata Credential Theft": [
        "169.254.169.254",
        "metadata service",
        "instance metadata",
    ],

    "IAM Privilege Escalation": [
        "iam privilege",
        "assume role",
        "iam:passrole",
    ],

    "Container Escape": [
        "container escape",
        "privileged container",
        "runc",
    ],

    "SSRF": [
        "ssrf",
    ],

    "XSS": [
        "xss",
        "cross-site scripting",
    ],

    "SQL Injection": [
        "sqli",
        "sql injection",
    ],
}

# =========================
# HELPERS
# =========================

def slug(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")[:90]


def node_id(path: Path, title: str) -> str:
    raw = f"{path}:{title}"
    digest = hashlib.sha1(raw.encode()).hexdigest()[:10]
    return f"{slug(title)}_{digest}"


def clean_markdown(text: str) -> str:
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def normalize_line(line: str) -> str:
    line = line.strip("-* 0123456789.")
    line = re.sub(r"\s+", " ", line)
    return line[:260]


# =========================
# FILE FILTER
# =========================

def should_include_file(path: Path) -> bool:
    p = str(path).lower()
    return any(x in p for x in FOCUS_PATHS)


# =========================
# DOMAIN DETECTION
# =========================

def detect_domains(text: str, path: Path) -> list[str]:

    p = str(path).lower()
    s = text.lower()

    found = set()

    # PATH BASED

    if "pentesting-web" in p:
        found.add("web")

    if "windows-hardening" in p:
        found.add("windows_infra")

    if "linux-hardening" in p:
        found.add("linux_infra")

    if any(x in p for x in [
        "active-directory",
        "ad-certificates",
        "kerberos",
        "ntlm",
    ]):
        found.add("active_directory")

    if "network-services-pentesting" in p and "pentesting-web" not in p:
        found.add("network_services")

    if any(x in p for x in [
        "kubernetes",
        "docker",
    ]):
        found.add("containers")

    if any(x in p for x in [
        "cloud",
        "aws",
    ]):
        found.add("aws")

    if "azure" in p:
        found.add("azure")

    if any(x in p for x in [
        "gcp",
        "google-cloud",
    ]):
        found.add("gcp")

    # TEXT BASED

    for domain, hints in DOMAIN_HINTS.items():

        hits = sum(1 for h in hints if h in s)

        threshold = 2

        if hits >= threshold:
            found.add(domain)

    # CLEAN FALSE POSITIVES

    if "pentesting-web" in p:
        found.discard("windows_infra")
        found.discard("aws")
        found.discard("azure")
        found.discard("gcp")

    return sorted(found) or ["infra_general"]


# =========================
# TOOLS
# =========================

def detect_tools(text: str) -> list[str]:

    s = text.lower()

    return sorted({
        tool
        for tool in TOOL_WORDS
        if re.search(rf"\b{re.escape(tool)}\b", s)
    })


# =========================
# PRIMITIVES
# =========================

def extract_primitives(text: str) -> list[str]:

    s = text.lower()

    primitives = []

    for primitive, hints in PRIMITIVE_MAP.items():

        if any(h in s for h in hints):
            primitives.append(primitive)

    return sorted(set(primitives))


# =========================
# TYPE
# =========================

def detect_type(text: str, primitives: list[str]) -> str:

    s = text.lower()

    if primitives:
        return "technique"

    if any(x in s for x in [
        "privilege escalation",
        "exploit",
        "abuse",
        "lateral movement",
    ]):
        return "technique"

    if any(x in s for x in [
        "checklist",
        "methodology",
        "enumeration",
    ]):
        return "methodology"

    if any(x in s for x in [
        "tool",
        "usage",
        "syntax",
    ]):
        return "tooling"

    return "knowledge"


# =========================
# ACTIONS
# =========================

def extract_actions(text: str) -> list[str]:

    actions = []

    action_words = (
        r"run|use|execute|modify|request|enumerate|check|abuse|"
        r"exploit|dump|read|write|upload|download|bypass|"
        r"authenticate|impersonate|connect|scan|query|list|"
        r"create|grant|take|pivot|access|extract|forge|relay|"
        r"spray|crack|capture|craft|trigger"
    )

    for line in text.splitlines():

        l = normalize_line(line)

        if len(l) < 10:
            continue

        if re.search(rf"\b({action_words})\b", l, re.I):
            actions.append(l)

    return actions[:14]


# =========================
# CONDITIONS
# =========================

def extract_conditions(text: str) -> list[str]:

    conditions = []

    condition_words = (
        r"required|requires|if|when|must|needs|permission|rights|"
        r"privilege|writable|enabled|disabled|allowed|member|owner|"
        r"access|role|policy|misconfigured|vulnerable|"
        r"authenticated|unauthenticated|exposed"
    )

    for line in text.splitlines():

        l = normalize_line(line)

        if len(l) < 10:
            continue

        if re.search(rf"\b({condition_words})\b", l, re.I):
            conditions.append(l)

    return conditions[:12]


# =========================
# LEADS_TO
# =========================

def infer_leads_to(
    text: str,
    domains: list[str],
    primitives: list[str]
) -> list[str]:

    leads = set()

    s = text.lower()

    if "RCE" in primitives:
        leads.add("code_execution")

    if "Secret Disclosure" in primitives:
        leads.add("credential_access")
        leads.add("follow_on_exploitation")

    if "Template Injection" in primitives:
        leads.add("code_execution")

    if any(p in primitives for p in [
        "WriteDACL",
        "WriteOwner",
        "GenericAll",
        "GenericWrite",
        "DACL Abuse",
    ]):
        leads.add("object_control")
        leads.add("privilege_escalation")

    if "Certificate Abuse" in primitives:
        leads.add("certificate_authentication")
        leads.add("domain_escalation")

    if any(p in primitives for p in [
        "Kerberoasting",
        "ASREPRoast",
        "DCSync",
    ]):
        leads.add("credential_access")

    if any(p in primitives for p in [
        "SeImpersonatePrivilege",
        "Token Impersonation",
    ]):
        leads.add("local_privilege_escalation")

    if any(p in primitives for p in [
        "SUID Abuse",
        "sudo Abuse",
        "Writable Service",
    ]):
        leads.add("local_privilege_escalation")

    if "Metadata Credential Theft" in primitives:
        leads.add("cloud_credential_access")

    if "IAM Privilege Escalation" in primitives:
        leads.add("cloud_privilege_escalation")

    if "Container Escape" in primitives:
        leads.add("host_access")

    if any(p in primitives for p in [
        "XSS",
        "SQL Injection",
        "SSRF",
    ]):
        leads.add("web_exploitation")

    if "active_directory" in domains and "privilege escalation" in s:
        leads.add("domain_escalation")

    return sorted(leads)


# =========================
# MARKDOWN SPLIT
# =========================

def split_markdown(path: Path):

    raw = path.read_text(errors="ignore")

    raw = clean_markdown(raw)

    parts = re.split(r"\n(?=#{1,3}\s)", raw)

    for part in parts:

        part = part.strip()

        if len(part) < 350:
            continue

        first = part.splitlines()[0]

        title = first.strip("# ").strip()

        if not title:
            title = path.stem

        yield title, part


# =========================
# BUILD NODE
# =========================

def build_node(path: Path, title: str, text: str) -> dict:

    domains = detect_domains(text, path)

    tools = detect_tools(text)

    primitives = extract_primitives(text)

    node_type = detect_type(text, primitives)

    return {
        "id": node_id(path, title),
        "type": node_type,
        "name": title,
        "source_path": str(path),
        "domains": domains,
        "tags": sorted(set(
            domains +
            tools +
            primitives
        )),
        "related_tools": tools,
        "primitives": primitives,
        "conditions": extract_conditions(text),
        "actions": extract_actions(text),
        "leads_to": infer_leads_to(
            text,
            domains,
            primitives
        ),
        "summary": text[:1100],
    }


# =========================
# FILE ITERATOR
# =========================

def iter_markdown_files():

    for root, dirs, files in os.walk(
        SOURCES,
        followlinks=True
    ):

        for name in files:

            if name.endswith(".md"):

                yield Path(root) / name


# =========================
# MAIN
# =========================

def main():

    count = 0
    skipped = 0
    seen = 0

    print(f"[+] Scanning: {SOURCES}")

    for md in iter_markdown_files():

        seen += 1

        if not should_include_file(md):
            skipped += 1
            continue

        for title, text in split_markdown(md):

            node = build_node(
                md,
                title,
                text
            )

            out = NODES / f"{node['id']}.json"

            out.write_text(
                json.dumps(
                    node,
                    indent=2,
                    ensure_ascii=False
                )
            )

            count += 1

    print(f"[+] Seen markdown files: {seen}")
    print(f"[+] Generated nodes: {count}")
    print(f"[+] Skipped files: {skipped}")
    print(f"[+] Output dir: {NODES}")


if __name__ == "__main__":
    main()
