#!/usr/bin/env python3
import os
import re
import json
import sqlite3
from pathlib import Path
from typing import Any

import requests
import numpy as np
from mcp.server.fastmcp import FastMCP

_HERE = Path(__file__).parent

DB_PATH = os.getenv("HACKTRICKS_DB", str(_HERE / "hacktricks_rag.db"))
OLLAMA_URL = os.getenv("OLLAMA_EMBED_URL", "http://localhost:11434/api/embed")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")

BRAIN_DIR = os.getenv("BRAIN_DIR", str(_HERE / "brain"))
NODES_DIR = os.path.join(BRAIN_DIR, "graph", "nodes")
EDGES_FILE = os.path.join(BRAIN_DIR, "graph", "edges.json")

MAX_TOOL_OUTPUT = 7000
MAX_CONTEXT_CHARS = 22000

# Claude synthesis — smaller, cheaper context for internal LLM calls
MAX_CONTEXT_CHARS_SYNTH = 6000
MAX_TOOL_OUTPUT_SYNTH = 2000

# Claude API config (all optional — server works without them)
CLAUDE_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ASTAROTH_MODEL = os.getenv("ASTAROTH_MODEL", "claude-haiku-4-5")
ASTAROTH_MAX_TOKENS = int(os.getenv("ASTAROTH_MAX_TOKENS", "1024"))

mcp = FastMCP("astaroth")

# In-process caches — valid for the lifetime of the MCP server subprocess.
# Rebuilt on next server start if the DB or graph files change.
_chunks_cache: list[dict[str, Any]] | None = None
_nodes_cache: dict | None = None
_edges_cache: list | None = None
_claude_client: Any = None

_TACTICAL_SYSTEM = (
    "You are a tactical offensive security consultant for authorized engagements. "
    "Rules: stay grounded in provided context only; no invented tools, CVEs, or commands; "
    "validation-first before any risky action; short and operator-ready answers."
)

STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "have", "what",
    "how", "tell", "give", "using", "example", "examples", "command",
    "commands", "please", "about", "into", "onto", "there", "their",
    "said", "tool", "output", "result", "machine", "vulnerable"
}

REAL_TOOLS = [
    "nmap", "masscan", "rustscan", "ffuf", "gobuster", "feroxbuster",
    "nuclei", "burp", "sqlmap", "wpscan", "nikto", "netexec",
    "crackmapexec", "impacket", "bloodhound", "certipy", "ldapsearch",
    "rpcclient", "smbclient", "evil-winrm", "kerbrute", "rubeus",
    "mimikatz", "linpeas", "winpeas", "pspy", "lse",
    "linux-exploit-suggester", "docker", "kubectl", "aws", "az",
    "gcloud", "ghidra", "gdb", "gef", "pwndbg", "radare2", "checksec"
]


def clean_terms(text: str) -> list[str]:
    words = re.findall(r"[a-zA-Z0-9_\-\.]{3,}", text.lower())
    return [w for w in words if w not in STOPWORDS]


def enrich_query(q: str) -> str:
    extra = [
        "abuse", "misconfiguration", "attack path", "validation",
        "enumeration", "pivot", "post exploitation", "privilege escalation"
    ]
    return q.lower() + " " + " ".join(extra)


def embed(text: str) -> np.ndarray:
    r = requests.post(
        OLLAMA_URL,
        json={"model": EMBED_MODEL, "input": text[:6000]},
        timeout=120,
    )
    r.raise_for_status()
    return np.array(r.json()["embeddings"][0], dtype=np.float32)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / ((np.linalg.norm(a) * np.linalg.norm(b)) + 1e-9))


def load_chunks() -> list[dict[str, Any]]:
    global _chunks_cache
    if _chunks_cache is not None:
        return _chunks_cache

    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"RAG DB not found: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, path, title, text, embedding FROM chunks")

    rows = []
    for cid, path, title, text, emb_json in cur.fetchall():
        rows.append({
            "id": cid,
            "path": path,
            "title": title,
            "text": text,
            "embedding": np.array(json.loads(emb_json), dtype=np.float32),
        })

    conn.close()
    _chunks_cache = rows
    return rows


def detect_domain(text: str) -> str:
    s = text.lower()

    checks = [
        ("ad / identity",  r"\badcs\b|\besc[0-9]+\b|kerberos|ldap|bloodhound|domain admin|active directory|kerbrute|secretsdump|mimikatz|rubeus|impacket|dcsync|ntds|laps|gpo abuse|sid history|asrep|kerberoast|delegation|rbcd|shadow credentials"),
        ("windows",        r"windows|winpeas|powershell|ntlm|uac|seimpersonate|sebackup|sedebug|alwaysinstallelevated|registry|smb|wmi|wininrm|unquoted.*service|dll hijack|token impersonat"),
        ("linux",          r"linux|linpeas|sudo|suid|capabilities|cron|systemd|bash|/etc/shadow|/etc/passwd|lxd|nfs.*squash|cap_setuid|pspy"),
        ("cloud / aws",    r"\baws\b|amazon|iam.*role|s3.*bucket|ec2.*instance|lambda|sts:|cloudtrail|imdsv|169\.254\.169\.254|akia[0-9a-z]{16}|aws_access_key|awscli"),
        ("cloud / azure",  r"\bazure\b|microsoft\.com/azure|arm_|azurerm|managedidentity|keyvault|storage.*blob|app.*service.*msi|service.*principal|az login|azcli"),
        ("cloud / gcp",    r"\bgcp\b|\bgoogle cloud\b|gcloud|gsutil|serviceaccount.*gcp|metadata\.google\.internal|iam\.googleapis|roles/owner"),
        ("containers",     r"docker|kubernetes|k8s|kubectl|kubelet|kube-api|container|runc|pod\b|helm|trivy|namespace.*k8s|hostnetwork|hostpid|privileged.*container|etcd"),
        ("ci/cd / devops", r"github.actions|gitlab-ci|jenkinsfile|pipeline|\.github/workflows|ci_job_token|self.hosted.*runner|pull_request_target|oidc.*token|supply.chain|devops"),
        ("web",            r"xss|sqli|csrf|ssrf|idor|lfi|rfi|upload|jwt|cors|websocket|graphql|api.*endpoint|burp|ffuf|nuclei"),
        ("mobile",         r"android|ios|apk|ipa|mobile|frida|objection"),
        ("binary",         r"pwn|rop|heap|stack|format string|buffer overflow|gdb|ghidra|checksec"),
        ("network",        r"nmap|masscan|rustscan|ports|tcp|udp|snmp|ftp\b|ssh\b|rdp\b|winrm|telnet|vlan|ipv6"),
    ]

    for name, pattern in checks:
        if re.search(pattern, s):
            return name

    return "general offsec"


def detect_tool_output(text: str) -> str:
    s = text.lower()

    if "nmap scan report" in s or re.search(r"\d+/tcp\s+open", s):
        return "nmap"
    if "certipy" in s or "certificate templates" in s or re.search(r"\besc[0-9]+\b", s):
        return "certipy/adcs"
    if "secretsdump" in s or re.search(r"dumping.*credentials|ntds\.dit|administrator:500:", s):
        return "secretsdump/impacket"
    if "kerbrute" in s or re.search(r"valid username|valid login|as-rep.*krb5", s):
        return "kerbrute/ad-enum"
    if re.search(r"^dn:\s|samaccountname:|ldapsearch", s, re.MULTILINE):
        return "ldapsearch/ldap-enum"
    if "enum4linux" in s or ("domain name:" in s and "domain sid:" in s):
        return "enum4linux"
    if "bloodhound" in s or "shortest path" in s or ("owned" in s and "domain" in s):
        return "bloodhound"
    if "winpeas" in s or "seimpersonateprivilege" in s:
        return "winpeas/windows-privesc"
    if "linpeas" in s or ("suid" in s and "capabilities" in s):
        return "linpeas/linux-privesc"
    if re.search(r"\"apiversion\":|\"kind\":\s*\"(pod|role|clusterrole|secret)", s):
        return "kubectl/kubernetes"
    if re.search(r'"hostconfig":|"networkmode":|privileged.*true', s):
        return "docker-inspect"
    if "trivy" in s or re.search(r"cve-\d{4}-\d+.*(critical|high)", s):
        return "trivy/container-scan"
    if re.search(r"on:\s*\[?push|jobs:\n|uses:\s*actions/", s):
        return "github-actions-workflow"
    if "gitlab-ci" in s or "ci_job_token" in s or re.search(r"stages:\n|script:\n", s):
        return "gitlab-ci"
    if "jenkinsfile" in s or re.search(r"pipeline\s*\{|agent\s+any", s):
        return "jenkinsfile"
    if re.search(r"arn:aws:|aws_access_key|\"userid\":|\"account\":", s):
        return "cloud/aws"
    if re.search(r"\"roledefinitionname\":|az login|microsoft\.com", s):
        return "cloud/azure"
    if re.search(r"serviceaccount.*gcp|gcloud|gsutil|\.googleapis\.com", s):
        return "cloud/gcp"
    if "prowler" in s:
        return "prowler"
    if "scoutsuite" in s:
        return "scoutsuite"
    if "http" in s and ("server:" in s or "x-powered-by" in s):
        return "web output"

    return "unknown / mixed"


def keyword_score(query: str, chunk: dict[str, Any]) -> float:
    q = set(clean_terms(query))
    if not q:
        return 0.0

    path = chunk["path"].lower()
    title = chunk["title"].lower()
    text = chunk["text"][:3500].lower()

    score = 0.0
    for term in q:
        if term in title:
            score += 3.0
        if term in path:
            score += 2.0
        if term in text:
            score += 1.0

    return min(score, 20.0) / 20.0


def domain_score(domain: str, chunk: dict[str, Any]) -> float:
    path = chunk["path"].lower()

    hints = {
        "ad / identity":   ["active-directory", "windows-hardening", "ntlm", "kerberos", "ad-certificates", "lateral-movement", "post-exploitation"],
        "windows":         ["windows-hardening", "windows-local-privilege", "post-exploitation"],
        "linux":           ["linux-hardening", "linux-privilege-escalation"],
        "web":             ["pentesting-web", "network-services-pentesting", "generic-methodologies"],
        "cloud / aws":     ["cloud-security", "aws", "amazon"],
        "cloud / azure":   ["cloud-security", "azure", "microsoft"],
        "cloud / gcp":     ["cloud-security", "gcp", "google"],
        "containers":      ["docker", "kubernetes", "containers", "cloud-security"],
        "ci/cd / devops":  ["cloud-security", "generic-methodologies", "pentesting-web"],
        "mobile":          ["mobile-pentesting", "android", "ios"],
        "binary":          ["binary-exploitation", "reversing"],
        "network":         ["network-services-pentesting", "pentesting"],
    }

    if domain not in hints:
        return 0.0

    return 1.0 if any(h in path for h in hints[domain]) else 0.0


def offensive_path_boost(chunk: dict[str, Any]) -> float:
    path = chunk["path"].lower()
    title = chunk["title"].lower()

    boost = 0.0

    high_signal = [
        "privilege-escalation", "active-directory", "windows-local-privilege",
        "pentesting-web", "cloud-security", "linux-hardening", "lateral-movement",
        "post-exploitation", "ad-certificates", "kerberos", "ntlm"
    ]

    for item in high_signal:
        if item in path or item in title:
            boost += 0.05

    return min(boost, 0.20)


def retrieve(query: str, top_k: int = 12):
    enriched = enrich_query(query)
    qv = embed(enriched)
    domain = detect_domain(query)
    chunks = load_chunks()

    results = []

    for ch in chunks:
        sem = cosine(qv, ch["embedding"])
        key = keyword_score(enriched, ch)
        dom = domain_score(domain, ch)
        boost = offensive_path_boost(ch)

        final = (sem * 0.55) + (key * 0.25) + (dom * 0.10) + boost

        results.append({
            **ch,
            "score": final,
            "semantic_score": sem,
            "keyword_score": key,
            "domain_score": dom,
            "boost_score": boost,
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return domain, results[:top_k]


def build_context(results: list[dict[str, Any]]) -> str:
    blocks = []
    total = 0

    for r in results:
        text = r["text"][:3200]
        block = (
            f"### Source: {r['path']}\n"
            f"### Section: {r['title']}\n"
            f"### Score: {r['score']:.3f} "
            f"(semantic={r['semantic_score']:.3f}, "
            f"keyword={r['keyword_score']:.3f}, "
            f"domain={r['domain_score']:.3f}, "
            f"boost={r['boost_score']:.3f})\n\n"
            f"{text}"
        )

        if total + len(block) > MAX_CONTEXT_CHARS:
            break

        blocks.append(block)
        total += len(block)

    return "\n\n---\n\n".join(blocks)


# =========================
# CLAUDE SYNTHESIS
# =========================

def _get_claude_client():
    global _claude_client
    if _claude_client is None:
        try:
            import anthropic
            _claude_client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        except ImportError:
            raise RuntimeError("anthropic package not installed — run: pip install anthropic")
    return _claude_client


def build_context_compact(results: list[dict[str, Any]]) -> str:
    """Stripped-down context for Claude synthesis calls — no score metadata, tighter per-chunk limit."""
    blocks = []
    total = 0
    for r in results:
        block = f"[{r['title']}]\n{r['text'][:1200]}"
        if total + len(block) > MAX_CONTEXT_CHARS_SYNTH:
            break
        blocks.append(block)
        total += len(block)
    return "\n---\n".join(blocks)


def format_graph_node_compact(node: dict) -> str:
    parts = [f"## {node.get('name')} ({node.get('type', '')})"]
    if node.get("primitives"):
        parts.append(f"Primitives: {', '.join(node['primitives'])}")
    if node.get("leads_to"):
        parts.append(f"Leads to: {', '.join(node['leads_to'])}")
    if node.get("related_tools"):
        parts.append(f"Tools: {', '.join(node['related_tools'])}")
    return "\n".join(parts)


def graph_lookup_compact(query: str, limit: int = 3) -> str:
    matches = graph_search_nodes(query, limit=limit)
    if not matches:
        return ""
    return "\n\n".join(format_graph_node_compact(n) for n in matches)


def _call_claude(user_message: str) -> str | None:
    """Call Claude API for synthesis. Returns None if no API key is configured."""
    if not CLAUDE_API_KEY:
        return None
    try:
        import anthropic
        client = _get_claude_client()
        response = client.messages.create(
            model=ASTAROTH_MODEL,
            max_tokens=ASTAROTH_MAX_TOKENS,
            system=[{
                "type": "text",
                "text": _TACTICAL_SYSTEM,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text
    except anthropic.APIError as e:
        return f"[Claude API error: {e}]\n\nFalling back to raw context:\n\n{user_message}"
    except Exception as e:
        return f"[Claude synthesis error: {e}]\n\nFalling back to raw context:\n\n{user_message}"


# =========================
# GRAPH
# =========================

def load_graph_nodes() -> dict:
    global _nodes_cache
    if _nodes_cache is not None:
        return _nodes_cache

    nodes = {}

    if not os.path.isdir(NODES_DIR):
        return nodes

    for name in os.listdir(NODES_DIR):
        if not name.endswith(".json"):
            continue

        path = os.path.join(NODES_DIR, name)

        try:
            with open(path, "r", encoding="utf-8") as f:
                node = json.load(f)
                nodes[node["id"]] = node
        except Exception:
            continue

    _nodes_cache = nodes
    return nodes


def load_graph_edges() -> list:
    global _edges_cache
    if _edges_cache is not None:
        return _edges_cache

    if not os.path.exists(EDGES_FILE):
        return []

    try:
        with open(EDGES_FILE, "r", encoding="utf-8") as f:
            result = json.load(f)
    except Exception:
        result = []

    _edges_cache = result
    return result


def graph_search_nodes(query: str, limit: int = 8) -> list:
    q = query.lower()
    nodes = load_graph_nodes()
    matches = []

    for node in nodes.values():
        blob = json.dumps(node).lower()

        if q in blob:
            matches.append(node)

    return matches[:limit]


def graph_related_edges(node_id: str, limit: int = 25) -> list:
    edges = load_graph_edges()
    found = []

    for edge in edges:
        if edge.get("from") == node_id or edge.get("to") == node_id:
            found.append(edge)

    return found[:limit]


def format_graph_node(node: dict, edges: list) -> str:
    lines = []

    lines.append(f"## {node.get('name')}")
    lines.append(f"ID: {node.get('id')}")
    lines.append(f"Type: {node.get('type')}")
    lines.append(f"Domains: {', '.join(node.get('domains', []))}")
    lines.append(f"Primitives: {', '.join(node.get('primitives', []))}")
    lines.append(f"Leads to: {', '.join(node.get('leads_to', []))}")
    lines.append(f"Tools: {', '.join(node.get('related_tools', []))}")

    if node.get("conditions"):
        lines.append("\nConditions:")
        for c in node["conditions"][:6]:
            lines.append(f"- {c}")

    if node.get("actions"):
        lines.append("\nActions:")
        for a in node["actions"][:8]:
            lines.append(f"- {a}")

    if edges:
        lines.append("\nRelations:")
        for e in edges[:12]:
            lines.append(
                f"- {e.get('from')} --[{e.get('type')}]--> {e.get('to')}"
            )

    return "\n".join(lines)


# =========================
# SESSION
# =========================

_active_session: Any = None


def _get_session():
    global _active_session
    if _active_session is not None:
        return _active_session
    try:
        from engine import session as _sess_mod
        s = _sess_mod.load_active()
        if s:
            _active_session = s
        return _active_session
    except Exception:
        return None


def _session_context_block() -> str:
    s = _get_session()
    if s is None:
        return ""
    try:
        from engine.reasoning import build_engagement_context
        return "\n\nACTIVE ENGAGEMENT CONTEXT:\n" + build_engagement_context(s)
    except Exception:
        return ""


# =========================
# MCP TOOLS
# =========================

@mcp.tool()
def engagement_new(name: str, scope: str = "") -> str:
    """Start a new engagement session. Tracks hosts, creds, findings, and attack paths."""
    global _active_session
    try:
        from engine import session as _sess_mod
        _active_session = _sess_mod.create(name, scope)
        return f"Engagement '{name}' created.\nScope: {scope or 'not set'}\nSession: {_active_session.db_path}"
    except Exception as e:
        return f"Error creating engagement: {e}"


@mcp.tool()
def engagement_load(name: str) -> str:
    """Load an existing engagement session by name."""
    global _active_session
    try:
        from engine import session as _sess_mod
        s = _sess_mod.load(name)
        if s is None:
            available = _sess_mod.list_sessions()
            return f"No session named '{name}'.\nAvailable: {', '.join(available) or 'none'}"
        _active_session = s
        summary = s.summary()
        return (
            f"Loaded engagement: {name}\n"
            f"Hosts: {len(summary['hosts'])}  "
            f"Creds: {len(summary['credentials'])}  "
            f"Findings: {len(summary['findings'])}  "
            f"Paths: {len(summary['paths'])}"
        )
    except Exception as e:
        return f"Error loading engagement: {e}"


@mcp.tool()
def engagement_list() -> str:
    """List all saved engagement sessions."""
    try:
        from engine import session as _sess_mod
        sessions = _sess_mod.list_sessions()
        if not sessions:
            return "No saved engagements."
        active = _active_session.name if _active_session else ""
        lines = []
        for name in sessions:
            marker = " [active]" if name == active else ""
            lines.append(f"  {name}{marker}")
        return "Saved engagements:\n" + "\n".join(lines)
    except Exception as e:
        return f"Error listing engagements: {e}"


@mcp.tool()
def engagement_status() -> str:
    """Show full status of the active engagement: hosts, credentials, findings, attack paths."""
    s = _get_session()
    if s is None:
        return "No active engagement. Use engagement_new or engagement_load first."
    try:
        from engine.reasoning import build_engagement_context, infer_paths
        infer_paths(s, lambda q, limit=3: graph_search_nodes(q, limit=limit))
        return build_engagement_context(s, max_chars=8000)
    except Exception as e:
        return f"Error reading engagement status: {e}"


@mcp.tool()
def ingest(tool_output: str, source_tool: str = "", host: str = "") -> str:
    """
    Parse tool output (nmap, certipy, netexec, bloodhound, winpeas, linpeas, or generic)
    and store findings into the active engagement session.
    """
    s = _get_session()
    if s is None:
        return "No active engagement. Use engagement_new first, then ingest."
    try:
        from engine.parsers import auto_parse
        from engine.reasoning import infer_paths
        result = auto_parse(tool_output)
        parser = result["parser"]
        confidence = result["confidence"]

        n_hosts = n_services = n_creds = n_findings = 0

        for h in result.get("hosts", []):
            ip = h.get("ip", "").strip()
            if not ip:
                continue
            target_ip = host if host and not h.get("ip") else ip
            s.add_host(target_ip, h.get("hostname", ""), h.get("os", ""))
            n_hosts += 1
            for svc in h.get("services", []):
                s.add_service(target_ip, svc["port"], svc.get("protocol", "tcp"),
                              svc.get("service", ""), svc.get("version", ""), svc.get("banner", ""))
                n_services += 1

        for c in result.get("credentials", []):
            s.add_credential(c["username"], c.get("secret", ""), c.get("secret_type", "password"),
                             c.get("domain", ""), source_tool or c.get("source", ""))
            n_creds += 1

        for f in result.get("findings", []):
            target_ip = host if host and not f.get("host_ip") else f.get("host_ip", "")
            s.add_finding(f["title"], f.get("description", ""), f.get("evidence", ""),
                         target_ip, f.get("type", ""), f.get("severity", "medium"))
            n_findings += 1

        new_paths = infer_paths(s, lambda q, limit=3: graph_search_nodes(q, limit=limit))
        s.log("ingest", f"Ingested {source_tool or parser} output",
              {"parser": parser, "hosts": n_hosts, "creds": n_creds, "findings": n_findings})

        lines = [
            f"Ingested via parser: {parser} (confidence={confidence})",
            f"  Hosts added/updated: {n_hosts}",
            f"  Services: {n_services}",
            f"  Credentials: {n_creds}",
            f"  Findings: {n_findings}",
            f"  Attack paths inferred: {len(new_paths)}",
        ]
        if n_findings > 0:
            lines.append("\nKey findings:")
            for f in result.get("findings", [])[:5]:
                lines.append(f"  [{f['severity'].upper()}] {f['title']}")
        if new_paths:
            lines.append("\nInferred paths:")
            for p in new_paths[:5]:
                lines.append(f"  [hypothesized] {p['technique']}: {p.get('from_node','')} → {p.get('to_node','')}")
        return "\n".join(lines)
    except Exception as e:
        return f"Ingest error: {e}"


@mcp.tool()
def add_cred(username: str, secret: str, secret_type: str = "password",
             domain: str = "", source: str = "") -> str:
    """Manually add a credential to the active engagement."""
    s = _get_session()
    if s is None:
        return "No active engagement."
    try:
        cid = s.add_credential(username, secret, secret_type, domain, source)
        dom = f"{domain}\\" if domain else ""
        s.log("add_cred", f"Added credential for {dom}{username}")
        return f"Credential added: {dom}{username} ({secret_type})"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def add_finding(title: str, description: str = "", evidence: str = "",
                host: str = "", severity: str = "medium") -> str:
    """Manually add a finding to the active engagement."""
    s = _get_session()
    if s is None:
        return "No active engagement."
    try:
        fid = s.add_finding(title, description, evidence, host, "", severity)
        s.log("add_finding", f"Added finding: {title}")
        return f"Finding added [{severity.upper()}]: {title}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def mark_path(technique: str, status: str, notes: str = "") -> str:
    """
    Update the status of an attack path.
    Status: hypothesized | attempted | confirmed | failed
    """
    s = _get_session()
    if s is None:
        return "No active engagement."
    valid = {"hypothesized", "attempted", "confirmed", "failed"}
    if status not in valid:
        return f"Invalid status '{status}'. Use: {', '.join(sorted(valid))}"
    try:
        s.upsert_path(technique, status=status, notes=notes)
        s.log("mark_path", f"{technique} → {status}")
        return f"Path updated: {technique} → {status}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def reason(question: str = "") -> str:
    """
    Reason over the full engagement state. Combines session findings, knowledge graph,
    and HackTricks context to produce a prioritized attack analysis.
    If no question is given, produces a full engagement situation report.
    """
    s = _get_session()
    if s is None:
        return "No active engagement. Use engagement_new + ingest first."
    try:
        from engine.reasoning import build_engagement_context, infer_paths
        infer_paths(s, lambda q, limit=3: graph_search_nodes(q, limit=limit))
        eng_context = build_engagement_context(s, max_chars=3000)

        q = question or "What is the current engagement state and what are the best next attack paths?"
        domain, results = retrieve(q, top_k=8)
        rag_context = build_context_compact(results)
        graph_context = graph_lookup_compact(q, limit=4)

        paths = s.get_paths()
        confirmed = [p for p in paths if p["status"] == "confirmed"]
        hypothesized = [p for p in paths if p["status"] == "hypothesized"]
        failed = [p for p in paths if p["status"] == "failed"]

        user_msg = (
            f"{eng_context}\n\n"
            f"QUESTION: {q}\n\n"
            f"CONFIRMED PATHS ({len(confirmed)}):\n" +
            "\n".join(f"  {p['technique']}: {p.get('from_node','')} → {p.get('to_node','')}" for p in confirmed[:5]) +
            f"\n\nHYPOTHESIZED PATHS ({len(hypothesized)}):\n" +
            "\n".join(f"  {p['technique']}: {p.get('from_node','')} → {p.get('to_node','')} | {p.get('notes','')}" for p in hypothesized[:8]) +
            f"\n\nFAILED PATHS: {', '.join(p['technique'] for p in failed[:5]) or 'none'}\n\n"
            f"KNOWLEDGE GRAPH:\n{graph_context}\n\n"
            f"HACKTRICKS CONTEXT:\n{rag_context}\n\n"
            "Respond with:\n"
            "[Current Position]\n"
            "[Highest-Value Paths] (ranked, with specific commands)\n"
            "[Immediate Next Actions]\n"
            "[What to Validate]\n"
            "[Missing Data]"
        )

        result = _call_claude(user_msg)
        if result:
            return result

        return user_msg
    except Exception as e:
        return f"Reasoning error: {e}"


@mcp.tool()
def health(clear_cache: bool = False) -> str:
    global _chunks_cache, _nodes_cache, _edges_cache

    if clear_cache:
        _chunks_cache = None
        _nodes_cache = None
        _edges_cache = None

    chunks = load_chunks()
    nodes = load_graph_nodes()
    edges = load_graph_edges()

    cache_note = "(cache cleared and reloaded)" if clear_cache else "(from cache)" if not clear_cache else ""

    synth_status = f"enabled (model={ASTAROTH_MODEL}, max_tokens={ASTAROTH_MAX_TOKENS})" if CLAUDE_API_KEY else "disabled (set ANTHROPIC_API_KEY to enable)"
    s = _get_session()
    session_status = f"active ({s.name})" if s else "none (use engagement_new to start)"

    return (
        f"OK {cache_note}\n"
        f"RAG chunks: {len(chunks)}\n"
        f"Graph nodes: {len(nodes)}\n"
        f"Graph edges: {len(edges)}\n"
        f"DB: {DB_PATH}\n"
        f"Brain: {BRAIN_DIR}\n"
        f"Embed URL: {OLLAMA_URL}\n"
        f"Embed model: {EMBED_MODEL}\n"
        f"Claude synthesis: {synth_status}\n"
        f"Session: {session_status}"
    )


@mcp.tool()
def search_hacktricks(query: str, top_k: int = 10) -> str:
    domain, results = retrieve(query, top_k=top_k)

    out = [f"Detected domain: {domain}\n"]
    for r in results:
        out.append(
            f"[{r['score']:.3f}] {r['title']}\n"
            f"{r['path']}\n"
            f"{r['text'][:1000]}"
        )

    return "\n\n---\n\n".join(out)


@mcp.tool()
def graph_lookup(query: str, limit: int = 5) -> str:
    matches = graph_search_nodes(query, limit=limit)

    if not matches:
        return f"No graph nodes matched query: {query}"

    out = []

    for node in matches:
        edges = graph_related_edges(node["id"])
        out.append(format_graph_node(node, edges))

    return "\n\n---\n\n".join(out)


@mcp.tool()
def consult(question: str, tool_output: str = "", top_k: int = 12) -> str:
    combined = question
    if tool_output:
        combined += "\n\nOperator tool output:\n" + tool_output[:MAX_TOOL_OUTPUT]

    domain, results = retrieve(combined, top_k=top_k)
    output_type = detect_tool_output(tool_output)
    session_ctx = _session_context_block()

    if CLAUDE_API_KEY:
        context = build_context_compact(results)
        graph_context = graph_lookup_compact(question, limit=3)
        user_msg = (
            f"Domain: {domain}\nTool output type: {output_type}\n"
            f"{session_ctx}\n\n"
            f"QUESTION:\n{question}\n\n"
            f"TOOL OUTPUT:\n{tool_output[:MAX_TOOL_OUTPUT_SYNTH] if tool_output else '[none]'}\n\n"
            f"GRAPH CONTEXT:\n{graph_context}\n\n"
            f"KNOWLEDGE:\n{context}\n\n"
            f"Respond with these sections:\n"
            f"[Situation Read]\n[What Actually Matters]\n[Fast Validation]\n"
            f"[Likely Paths]\n[Next Actions]\n[Decision Points]\n[Fallback Ideas]"
        )
        result = _call_claude(user_msg)
        if result is not None:
            return result

    context = build_context(results)
    graph_context = graph_lookup(question, limit=4)

    return f"""
You are a senior offensive security consultant assisting an authorized operator during an engagement.

You are not a documentation summarizer.
You are a tactical decision support system.

Detected topic/domain: {domain}
Detected tool output type: {output_type}

Operator question:
{question}

Operator tool output:
{tool_output[:MAX_TOOL_OUTPUT] if tool_output else "[none]"}

Relevant graph knowledge:
{graph_context}

Relevant HackTricks RAG context:
{context}

Hard rules:
- Do not invent tools, commands, CVEs, or facts.
- Do not output commands unless they are real tools or clearly supported by context.
- Prefer real tools only, such as: {", ".join(REAL_TOOLS)}.
- If the context is weak, say what evidence is missing.
- Give validation-first guidance before risky actions.
- Adapt to the operator's domain: web, AD, cloud, infra, Linux, Windows, binary, mobile, or network.
- Do not produce generic documentation summaries.
- Keep the answer tactical and useful.

Respond exactly with:

[Situation Read]
What the operator likely has.

[What Actually Matters]
The key condition that determines whether this path is worth continuing.

[Fast Validation]
The minimum useful checks to confirm or deny the path.

[Likely Paths]
Realistic paths that could follow from this finding.

[Next Actions]
Concrete actions/tools for authorized validation.

[Decision Points]
What result means continue, pivot, or stop.

[Fallback Ideas]
Alternate checks if the main path fails.
"""


@mcp.tool()
def analyze_tool_output(tool_output: str, goal: str = "suggest next operational steps", top_k: int = 12) -> str:
    output_type = detect_tool_output(tool_output)
    query = f"{goal}\nDetected output type: {output_type}\n\n{tool_output[:MAX_TOOL_OUTPUT]}"

    domain, results = retrieve(query, top_k=top_k)
    session_ctx = _session_context_block()

    if CLAUDE_API_KEY:
        context = build_context_compact(results)
        graph_context = graph_lookup_compact(tool_output[:500], limit=3)
        user_msg = (
            f"Domain: {domain}\nTool output type: {output_type}\n"
            f"{session_ctx}\n\n"
            f"GOAL:\n{goal}\n\n"
            f"TOOL OUTPUT:\n{tool_output[:MAX_TOOL_OUTPUT_SYNTH]}\n\n"
            f"GRAPH CONTEXT:\n{graph_context}\n\n"
            f"KNOWLEDGE:\n{context}\n\n"
            f"Respond with these sections:\n"
            f"[What Stands Out]\n[Likely Meaning]\n[Next Checks]\n"
            f"[Useful Tools]\n[Possible Chain]\n[Missing Data]"
        )
        result = _call_claude(user_msg)
        if result is not None:
            return result

    context = build_context(results)
    graph_context = graph_lookup(tool_output[:1000], limit=4)

    return f"""
You are a senior offensive security consultant reviewing tool output from an authorized assessment.

Detected topic/domain: {domain}
Detected output type: {output_type}

Goal:
{goal}

Tool output:
{tool_output[:MAX_TOOL_OUTPUT]}

Relevant graph knowledge:
{graph_context}

Relevant HackTricks context:
{context}

Hard rules:
- Stay grounded in the provided output.
- Do not invent missing findings.
- Do not invent tool names or fake commands.
- If evidence is missing, ask for the exact missing output.
- Provide next steps that help the operator decide what to do next.

Respond exactly with:

[What Stands Out]
Important observations from the output.

[Likely Meaning]
What those observations probably imply.

[Next Checks]
Specific checks to run next.

[Useful Tools]
Real tools that fit this situation.

[Possible Chain]
How this might connect to a broader attack path.

[Missing Data]
What the operator should paste next.
"""


@mcp.tool()
def plan_next_steps(
    situation: str,
    objective: str = "progress the engagement",
    constraints: str = "",
    top_k: int = 12
) -> str:
    query = f"""
Situation:
{situation}

Objective:
{objective}

Constraints:
{constraints}
"""

    domain, results = retrieve(query, top_k=top_k)
    session_ctx = _session_context_block()

    if CLAUDE_API_KEY:
        context = build_context_compact(results)
        graph_context = graph_lookup_compact(situation, limit=3)
        user_msg = (
            f"Domain: {domain}\n"
            f"{session_ctx}\n\n"
            f"SITUATION:\n{situation}\n\n"
            f"OBJECTIVE:\n{objective}\n\n"
            f"CONSTRAINTS:\n{constraints if constraints else '[none]'}\n\n"
            f"GRAPH CONTEXT:\n{graph_context}\n\n"
            f"KNOWLEDGE:\n{context}\n\n"
            f"Respond with these sections:\n"
            f"[Current Position]\n[Best Next Move]\n[Parallel Checks]\n"
            f"[Potential Pivots]\n[Stop Conditions]"
        )
        result = _call_claude(user_msg)
        if result is not None:
            return result

    context = build_context(results)
    graph_context = graph_lookup(situation, limit=4)

    return f"""
You are a senior red team consultant helping plan next actions in an authorized engagement.

Detected topic/domain: {domain}

Situation:
{situation}

Objective:
{objective}

Constraints:
{constraints if constraints else "[none]"}

Relevant graph knowledge:
{graph_context}

Relevant HackTricks context:
{context}

Hard rules:
- Do not invent access the operator does not have.
- Start from the stated situation.
- Prefer low-noise validation before high-noise actions.
- Be practical and concise.

Respond exactly with:

[Current Position]
Where the operator likely is in the attack chain.

[Best Next Move]
The most useful next action and why.

[Parallel Checks]
Other checks worth running.

[Potential Pivots]
Where this could lead.

[Stop Conditions]
Signals that this path is not worth continuing.
"""


if __name__ == "__main__":
    mcp.run()
