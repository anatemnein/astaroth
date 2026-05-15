#!/usr/bin/env python3
import os
import re
import json
import sqlite3
from typing import Any

import requests
import numpy as np
from mcp.server.fastmcp import FastMCP

DB_PATH = os.getenv("HACKTRICKS_DB", "/home/quiet/astaroth/hacktricks_rag.db")
OLLAMA_URL = os.getenv("OLLAMA_EMBED_URL", "http://localhost:11434/api/embed")
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")

BRAIN_DIR = os.getenv("BRAIN_DIR", "/home/quiet/astaroth/brain")
NODES_DIR = os.path.join(BRAIN_DIR, "graph", "nodes")
EDGES_FILE = os.path.join(BRAIN_DIR, "graph", "edges.json")

MAX_TOOL_OUTPUT = 7000
MAX_CONTEXT_CHARS = 22000

mcp = FastMCP("hacktricks-consultant")

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
    return rows


def detect_domain(text: str) -> str:
    s = text.lower()

    checks = [
        ("ad / identity", r"\badcs\b|\besc[0-9]\b|kerberos|ldap|bloodhound|domain admin|active directory"),
        ("windows", r"windows|winpeas|powershell|ntlm|uac|seimpersonate|registry|smb"),
        ("linux", r"linux|linpeas|sudo|suid|capabilities|cron|systemd|bash"),
        ("web", r"xss|sqli|csrf|ssrf|idor|lfi|rfi|upload|jwt|cors|websocket|react|dom"),
        ("cloud", r"\baws\b|\bazure\b|\bgcp\b|iam|s3|lambda|metadata|sts|cloudtrail"),
        ("containers", r"docker|kubernetes|k8s|container|runc|pod|helm"),
        ("mobile", r"android|ios|apk|ipa|mobile"),
        ("binary", r"pwn|rop|heap|stack|format string|buffer overflow|gdb|ghidra"),
        ("network", r"nmap|ports|tcp|udp|snmp|ftp|ssh|rdp|winrm"),
    ]

    for name, pattern in checks:
        if re.search(pattern, s):
            return name

    return "general offsec"


def detect_tool_output(text: str) -> str:
    s = text.lower()

    if "nmap scan report" in s or re.search(r"\d+/tcp\s+open", s):
        return "nmap"
    if "certipy" in s or "certificate templates" in s or re.search(r"\besc[0-9]\b", s):
        return "certipy/adcs"
    if "bloodhound" in s or "shortest path" in s or ("owned" in s and "domain" in s):
        return "bloodhound"
    if "winpeas" in s or "seimpersonateprivilege" in s:
        return "winpeas/windows-privesc"
    if "linpeas" in s or ("suid" in s and "capabilities" in s):
        return "linpeas/linux-privesc"
    if "http" in s and ("server:" in s or "x-powered-by" in s):
        return "web output"
    if "aws_access_key" in s or "arn:aws" in s:
        return "cloud/aws"

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
        "ad / identity": ["active-directory", "windows-hardening", "ntlm", "kerberos", "ad-certificates"],
        "windows": ["windows-hardening"],
        "linux": ["linux-hardening"],
        "web": ["pentesting-web", "network-services-pentesting", "generic-methodologies"],
        "cloud": ["cloud-security", "aws", "azure", "gcp", "cloud"],
        "containers": ["docker", "kubernetes", "containers"],
        "mobile": ["mobile-pentesting", "android", "ios"],
        "binary": ["binary-exploitation", "reversing"],
        "network": ["network-services-pentesting", "pentesting"],
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
# GRAPH
# =========================

def load_graph_nodes() -> dict:
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

    return nodes


def load_graph_edges() -> list:
    if not os.path.exists(EDGES_FILE):
        return []

    try:
        with open(EDGES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


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
# MCP TOOLS
# =========================

@mcp.tool()
def health() -> str:
    chunks = load_chunks()
    nodes = load_graph_nodes()
    edges = load_graph_edges()
    return (
        f"OK\n"
        f"RAG chunks: {len(chunks)}\n"
        f"Graph nodes: {len(nodes)}\n"
        f"Graph edges: {len(edges)}\n"
        f"DB: {DB_PATH}\n"
        f"Brain: {BRAIN_DIR}"
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
