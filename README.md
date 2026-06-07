# Astaroth

> Stateful Offensive Security Copilot — MCP, RAG, Knowledge Graph, Engagement Memory.

Astaroth is a local-first operator support system for authorized red team engagements. It combines semantic knowledge retrieval, a structured attack technique graph, real tool output parsing, and persistent engagement state into a single MCP server that plugs into any LLM client.

---

## What it does

Instead of answering generic security questions, Astaroth tracks your engagement. You ingest tool output, it parses it into structured findings, infers attack paths, and reasons over everything it knows when you ask what to do next.

```
You run nmap, certipy, netexec → paste output into ingest()
Astaroth parses it → stores hosts, services, findings, credentials
You call reason() → it cross-references findings with 80+ technique patterns
               → generates ranked attack paths
               → pulls relevant HackTricks + graph context
               → returns a prioritized operator-ready analysis
```

---

## Coverage

| Domain | Tools parsed | Techniques |
|---|---|---|
| Active Directory | nmap, netexec, certipy, bloodhound, secretsdump, kerbrute, ldapsearch, enum4linux | Kerberoasting, ASREPRoast, ADCS ESC1-13, NTLM relay, unconstrained/constrained delegation, RBCD, shadow credentials, ACL abuse, GPO abuse, LAPS, cross-forest, DCSync |
| Windows | winpeas | SeImpersonate, SeBackup, SeDebug, AlwaysInstallElevated, unquoted service paths, DLL hijacking, AutoLogon, service binary hijack |
| Linux | linpeas | SUID, sudo NOPASSWD, capabilities, cron, docker/lxd/disk group, NFS no_root_squash, shadow read, passwd write |
| Cloud — AWS | AWS CLI JSON, Prowler, ScoutSuite | IAM privilege escalation, PassRole chains, IMDSv1 SSRF, public S3, CloudTrail disabled, confused deputy, Lambda admin role |
| Cloud — Azure | Azure CLI JSON | Owner/Contributor on external principals, managed identity abuse, public blob storage, Key Vault access |
| Cloud — GCP | gcloud JSON | SA owner role, allUsers bindings, GCS public buckets, metadata SSRF, Workload Identity Federation |
| Containers / K8s | kubectl JSON, docker inspect, trivy | Privileged container escape, docker socket mount, hostPath abuse, RBAC wildcards, SA cluster-admin bindings, etcd exposure, CVEs |
| CI/CD / DevOps | GitHub Actions, GitLab CI, Jenkinsfile, env dumps | Pipeline injection, pull_request_target abuse, OIDC misconfiguration, self-hosted runner pivot, plaintext secrets, supply chain |
| Network / Infra | nmap (XML + text) | Service enumeration, OS fingerprinting |

---

## Architecture

```
LLM Client (Claude Code / OpenWebUI / Claude Desktop)
           │
           ▼
    MCP Server (astaroth_mcp.py)
           │
    ┌──────┼──────────────────┐
    │      │                  │
    ▼      ▼                  ▼
RAG DB  Graph Brain      Engagement Session
(SQLite  (JSON nodes/     (SQLite per-engagement:
 9k+     edges from       hosts, services, creds,
 chunks) HackTricks)      findings, attack paths)
    │      │                  │
    └──────┴──────────────────┘
                  │
           Engine Layer
           ├── parsers/   (10 parsers, auto-dispatch)
           └── reasoning/ (80+ technique patterns, path inference)
```

All components run locally. The only optional external call is to the Anthropic API for Claude synthesis (disabled by default).

---

## MCP Tools

### Engagement management

| Tool | Description |
|---|---|
| `engagement_new(name, scope)` | Start a new engagement session |
| `engagement_load(name)` | Resume an existing engagement |
| `engagement_list()` | List all saved engagements |
| `engagement_status()` | Full situation report — hosts, creds, findings, attack paths |

### Ingestion

| Tool | Description |
|---|---|
| `ingest(tool_output, source_tool, host)` | Parse any tool output, store findings, auto-infer attack paths |
| `add_cred(username, secret, secret_type, domain, source)` | Manually add a credential |
| `add_finding(title, description, evidence, host, severity)` | Manually add a finding |
| `mark_path(technique, status, notes)` | Update path status: `hypothesized / attempted / confirmed / failed` |

### Analysis

| Tool | Description |
|---|---|
| `reason(question)` | Holistic engagement analysis — combines session state, graph, and HackTricks |
| `consult(question, tool_output)` | Ad-hoc question with optional tool output |
| `analyze_tool_output(tool_output, goal)` | Analyze tool output without storing to session |
| `plan_next_steps(situation, objective, constraints)` | Plan next actions from a described situation |

### Knowledge retrieval

| Tool | Description |
|---|---|
| `search_hacktricks(query)` | Direct semantic search over HackTricks RAG |
| `graph_lookup(query)` | Query the attack technique knowledge graph |
| `health()` | Server status — RAG, graph, session, Claude synthesis |

---

## Typical workflow

```
engagement_new("client-ad-2025", "10.10.10.0/24, domain: corp.local")

# Recon
ingest(<nmap output>)
ingest(<netexec smb output>)
ingest(<certipy find output>)
ingest(<bloodhound JSON>)

# Check what you have
engagement_status()

# Full analysis
reason("what is the fastest path to domain admin given current findings?")

# Track progress
mark_path("ESC1 — Certificate Abuse", "confirmed", "certipy req succeeded")
mark_path("NTLM Relay", "failed", "target has signing enforced")

# Continue with session context automatically in all tools
consult("I have a TGT for svc-backup, what can I do with it?")
```

---

## Installation

### Requirements

- Python 3.11+
- Ollama (for embeddings)
- An MCP-compatible client (Claude Code, Claude Desktop, OpenWebUI)

### Setup

```bash
git clone <repo>
cd astaroth
python -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### Pull embedding model

```bash
ollama pull nomic-embed-text
```

### Clone HackTricks

```bash
git clone https://github.com/HackTricks-wiki/hacktricks.git
```

### Build the RAG database

```bash
python ingest_hacktricks.py
```

This is incremental — safe to re-run. To force a full rebuild:

```bash
python ingest_hacktricks.py --rebuild
```

### Generate the knowledge graph

```bash
python generate_nodes.py
python generate_edges.py
```

Or use the helper script:

```bash
./scripts/rebuild_brain.sh
```

---

## MCP client configuration

### Claude Code / Claude Desktop

```json
{
  "mcpServers": {
    "astaroth": {
      "type": "stdio",
      "command": "/path/to/astaroth/env/bin/python",
      "args": ["/path/to/astaroth/astaroth_mcp.py"],
      "env": {
        "EMBED_MODEL": "nomic-embed-text",
        "OLLAMA_EMBED_URL": "http://localhost:11434/api/embed",
        "ANTHROPIC_API_KEY": "",
        "ASTAROTH_MODEL": "claude-haiku-4-5",
        "ASTAROTH_MAX_TOKENS": "1024"
      }
    }
  }
}
```

### OpenWebUI (air-gapped)

Connect via the MCP settings panel, pointing to `astaroth_mcp.py`. All inference stays local.

---

## Claude synthesis (optional)

When `ANTHROPIC_API_KEY` is set, the synthesis tools (`consult`, `analyze_tool_output`, `plan_next_steps`, `reason`) call Claude directly to produce a short synthesized answer instead of returning a raw context dump. Uses `claude-haiku-4-5` by default for low cost.

| Env var | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | _(empty)_ | Enable Claude synthesis |
| `ASTAROTH_MODEL` | `claude-haiku-4-5` | Model to use |
| `ASTAROTH_MAX_TOKENS` | `1024` | Max tokens per synthesis response |

When no key is set, tools return structured context prompts instead — works with any LLM client.

---

## Data privacy

Every component runs locally:

| Component | Location |
|---|---|
| MCP server | local subprocess (stdio) |
| RAG database | local SQLite (`hacktricks_rag.db`) |
| Embeddings | Ollama on `localhost:11434` |
| Knowledge graph | local JSON files (`brain/`) |
| Engagement sessions | local SQLite (`sessions/`) |

**Data leaves the machine only if:**
- `ANTHROPIC_API_KEY` is set (synthesis calls go to Anthropic)
- A cloud-backed LLM client is used (Claude Code, Claude Desktop)

For engagements involving customer data, use OpenWebUI + a local Ollama model with `ANTHROPIC_API_KEY` unset. Zero data leaves the machine.

---

## Configuration reference

| Env var | Default | Description |
|---|---|---|
| `HACKTRICKS_DB` | `./hacktricks_rag.db` | RAG database path |
| `BRAIN_DIR` | `./brain` | Knowledge graph directory |
| `EMBED_MODEL` | `nomic-embed-text` | Ollama embedding model |
| `OLLAMA_EMBED_URL` | `http://localhost:11434/api/embed` | Ollama endpoint |
| `ASTAROTH_SESSION_DIR` | `./sessions` | Engagement session storage |
| `ANTHROPIC_API_KEY` | _(empty)_ | Claude synthesis (optional) |
| `ASTAROTH_MODEL` | `claude-haiku-4-5` | Synthesis model |
| `ASTAROTH_MAX_TOKENS` | `1024` | Synthesis token cap |

---

## Scope

Astaroth is intended for authorized security testing, internal red team operations, labs, CTFs, and security research. Users are responsible for complying with all applicable laws and authorization requirements.

---

## Acknowledgements

- [HackTricks](https://github.com/HackTricks-wiki/hacktricks)
- [Ollama](https://ollama.com)
- [MCP ecosystem](https://modelcontextprotocol.io)
- Offensive security community
