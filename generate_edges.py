#!/usr/bin/env python3
import os
import json
from pathlib import Path

BRAIN = Path(os.environ.get("BRAIN_DIR", str(Path(__file__).parent / "brain")))
NODES_DIR = BRAIN / "graph" / "nodes"
EDGES_FILE = BRAIN / "graph" / "edges.json"

edges = []


def add_edge(src, dst, rel, reason=""):
    if not src or not dst or src == dst:
        return

    edge = {
        "from": src,
        "to": dst,
        "type": rel
    }

    if reason:
        edge["reason"] = reason

    if edge not in edges:
        edges.append(edge)


def load_nodes():
    nodes = []

    for path in NODES_DIR.glob("*.json"):
        try:
            nodes.append(json.loads(path.read_text()))
        except Exception:
            continue

    return nodes


def main():
    nodes = load_nodes()

    for node in nodes:
        node_id = node.get("id")
        name = node.get("name", "")
        primitives = node.get("primitives", [])
        leads_to = node.get("leads_to", [])
        tools = node.get("related_tools", [])
        domains = node.get("domains", [])

        # node -> primitive
        for primitive in primitives:
            add_edge(
                node_id,
                primitive,
                "has_primitive",
                f"{name} exposes or depends on {primitive}"
            )

        # primitive -> impact
        for primitive in primitives:
            if primitive in ["WriteDACL", "WriteOwner", "GenericAll", "GenericWrite", "DACL Abuse"]:
                add_edge(primitive, "object_control", "enables")
                add_edge("object_control", "privilege_escalation", "leads_to")

            if primitive == "Certificate Abuse":
                add_edge(primitive, "certificate_authentication", "enables")
                add_edge("certificate_authentication", "domain_escalation", "leads_to")

            if primitive in ["Kerberoasting", "ASREPRoast", "DCSync"]:
                add_edge(primitive, "credential_access", "leads_to")

            if primitive in ["SeImpersonatePrivilege", "Token Impersonation"]:
                add_edge(primitive, "local_privilege_escalation", "leads_to")

            if primitive in ["SUID Abuse", "sudo Abuse", "Writable Service"]:
                add_edge(primitive, "local_privilege_escalation", "leads_to")

            if primitive == "RCE":
                add_edge(primitive, "code_execution", "leads_to")

            if primitive == "Secret Disclosure":
                add_edge(primitive, "credential_access", "leads_to")

            if primitive == "Metadata Credential Theft":
                add_edge(primitive, "cloud_credential_access", "leads_to")

            if primitive == "IAM Privilege Escalation":
                add_edge(primitive, "cloud_privilege_escalation", "leads_to")

            if primitive == "Container Escape":
                add_edge(primitive, "host_access", "leads_to")

            if primitive in ["XSS", "SQL Injection", "SSRF"]:
                add_edge(primitive, "web_exploitation", "leads_to")

        # node -> leads_to
        for impact in leads_to:
            add_edge(node_id, impact, "leads_to", f"{name} may lead to {impact}")

        # node -> tools
        for tool in tools:
            add_edge(node_id, tool, "uses_tool", f"{name} references {tool}")

        # node -> domain
        for domain in domains:
            add_edge(node_id, domain, "belongs_to_domain")

    EDGES_FILE.write_text(json.dumps(edges, indent=2, ensure_ascii=False))

    print(f"[+] Loaded nodes: {len(nodes)}")
    print(f"[+] Generated edges: {len(edges)}")
    print(f"[+] Output: {EDGES_FILE}")


if __name__ == "__main__":
    main()
