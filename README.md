# Astaroth

> Offensive Security Copilot powered by MCP, RAG, Knowledge Graphs, and Local/Remote LLMs.

Astaroth is a local-first offensive security assistant designed for:

- Red Team operations
- Active Directory assessments
- Cloud security testing
- Infrastructure exploitation
- Internal network operations
- CTFs and labs
- Tool output analysis
- Attack path reasoning
- Operator decision support

Instead of acting like a generic chatbot, Astaroth behaves like an operator support system.

It combines:

- MCP (Model Context Protocol)
- Semantic RAG retrieval
- Knowledge graph traversal
- Local or remote LLM inference
- Attack chain reasoning
- Operational context expansion

---

# Features

## MCP Offensive Consultant

Astaroth exposes an MCP server that can be consumed by:

- OpenClaude
- Claude Desktop
- OpenWebUI
- Custom agent frameworks
- LangGraph
- Local copilots

The MCP layer provides:

- consultation
- attack path reasoning
- tool output interpretation
- next-step planning
- semantic retrieval
- graph expansion
- operational assistance

---

## Semantic RAG Engine

The project ingests HackTricks and converts it into searchable embeddings.

Capabilities:

- semantic search
- context-aware retrieval
- technique correlation
- infrastructure-focused knowledge lookup
- operator-oriented context building

---

## Knowledge Graph Brain

Astaroth automatically generates graph nodes and edges from offensive security documentation.

The graph contains:

- techniques
- primitives
- attack paths
- credential abuse chains
- cloud escalation paths
- AD escalation paths
- post-exploitation relationships

This enables reasoning flows such as:

```text
ESC2
→ certificate abuse
→ PKINIT
→ TGT
→ DCSync
````

---

# Current Focus

Astaroth is currently optimized for:

* Active Directory
* Windows Infrastructure
* Azure
* AWS
* GCP
* Linux privilege escalation
* Internal infrastructure assessments

---

# Architecture

```text
                ┌──────────────────┐
                │   OpenClaude     │
                │   OpenWebUI      │
                │   Claude Desktop │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │   MCP Server     │
                │ hacktricks_mcp.py│
                └────────┬─────────┘
                         │
         ┌───────────────┼────────────────┐
         ▼               ▼                ▼
 ┌────────────┐  ┌──────────────┐  ┌──────────────┐
 │ RAG Search │  │ Graph Brain  │  │ Attack Logic │
 └────────────┘  └──────────────┘  └──────────────┘
         │               │                │
         ▼               ▼                ▼
    SQLite DB       Nodes/Edges      Future Planner
```

---

# Requirements

## Recommended Environment

* Linux
* Python 3.11+
* Ollama OR Claude API
* 16GB+ RAM recommended
* NVIDIA GPU optional

---

# Installation

## Clone repository

```bash
git clone https://github.com/anatemnein/astaroth.git
cd astaroth
```

---

## Create virtual environment

```bash
python -m venv env
source env/bin/activate
```

---

## Install dependencies

```bash
pip install -r requirements.txt
```

---

# LLM Backends

Astaroth supports:

* Local models via Ollama
* Claude API
* OpenAI-compatible APIs
* Remote hosted inference

---

# Option 1 — Using Ollama (Local Models)

Install Ollama:

[https://ollama.com](https://ollama.com)

Pull recommended models:

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama pull nomic-embed-text
```

Recommended local models:

* qwen2.5:7b-instruct-q4_K_M
* qwen2.5-coder:7b-instruct-q4_K_M
* deepseek-r1:8b

---

# Option 2 — Using Claude API

If you do not want to run local models with Ollama, you can use Claude directly through Anthropic API.

Get an API key:

[https://console.anthropic.com/](https://console.anthropic.com/)

Export the API key:

```bash
export ANTHROPIC_API_KEY="your_api_key_here"
```

You can then configure your frontend/client to use Claude models such as:

* claude-3-5-sonnet
* claude-3-opus
* claude-sonnet-4

This is recommended for users who want:

* better reasoning
* stronger MCP/tool usage
* larger context windows
* higher quality operational guidance

without running large local models.

---

# Setup Knowledge Sources

Astaroth requires a local copy of HackTricks in order to build the offensive knowledge base.

Clone the official repository:

```bash
git clone https://github.com/HackTricks-wiki/hacktricks.git
```

Create the local source link:

```bash
mkdir -p brain/sources
ln -s ~/astaroth/hacktricks brain/sources/hacktricks
```

Then generate the graph and RAG database:

```bash
python generate_nodes.py
python generate_edges.py
python ingest_hacktricks.py
```

---

# Knowledge Sources & Attribution

Astaroth does not redistribute HackTricks content directly.

The project uses a local ingestion pipeline that allows operators to clone and process their own local copy of HackTricks for semantic retrieval and graph generation.

Users must manually clone the official HackTricks repository:

```bash
git clone https://github.com/HackTricks-wiki/hacktricks.git
```

Official HackTricks repository:

[https://github.com/HackTricks-wiki/hacktricks](https://github.com/HackTricks-wiki/hacktricks)

All original content, research, methodologies, and documentation belong to the HackTricks project and its contributors.

Astaroth acts as:

* a local indexing layer
* semantic retrieval engine
* graph-generation framework
* operator support system

and does not claim ownership over HackTricks content.

---

# Generate Brain Graph

## Generate nodes

```bash
python generate_nodes.py
```

## Generate edges

```bash
python generate_edges.py
```

---

# Build RAG Database

```bash
python ingest_hacktricks.py
```

---

# Running the MCP Server

```bash
python hacktricks_mcp.py
```

If it stays idle without output:

```text
MCP server is running correctly
```

---

# OpenClaude Integration

Add MCP server:

```bash
openclaude mcp add hacktricks-consultant -- \
  /home/user/astaroth/env/bin/python \
  /home/user/astaroth/hacktricks_mcp.py
```

---

# Claude Desktop Integration

Claude Desktop users can add the MCP server by editing the MCP configuration.

Example:

```json
{
  "mcpServers": {
    "hacktricks-consultant": {
      "command": "/home/user/astaroth/env/bin/python",
      "args": [
        "/home/user/astaroth/hacktricks_mcp.py"
      ]
    }
  }
}
```

---

# Example Usage

## Tool Output Analysis

```text
Use hacktricks-consultant analyze_tool_output.

Goal:
Identify likely attack paths.

Tool output:

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
445/tcp  open  smb
```

---

## Operator Consultation

```text
Use hacktricks-consultant consult.

Question:
I found anonymous SMB access on a Linux server. What should I validate next?
```

---

## Next-Step Planning

```text
Use hacktricks-consultant plan_next_steps.

Situation:
Low-privileged SSH access on Linux host.

Objective:
Privilege escalation.

Constraints:
Avoid noisy kernel exploits.
```

---

# Project Structure

```text
astaroth/
├── brain/
├── docs/
├── examples/
├── parsers/
├── scripts/
├── generate_nodes.py
├── generate_edges.py
├── graph_query.py
├── hacktricks_mcp.py
├── ingest_hacktricks.py
├── requirements.txt
└── README.md
```

---

# Project Roadmap

* [ ] Autonomous attack chain engine
* [ ] BloodHound parser
* [ ] Certipy parser
* [ ] NetExec parser
* [ ] WinPEAS parser
* [ ] Cloud attack graph
* [ ] Credential memory
* [ ] Session memory
* [ ] Multi-host reasoning
* [ ] Autonomous orchestration layer
* [ ] Tool execution engine
* [ ] Attack path prioritization
* [ ] Multi-agent reasoning

---

# Status

This project is under active development.

Current focus areas:

* graph expansion
* parser development
* attack path reasoning
* operational planning
* autonomous orchestration

---

# Disclaimer

Astaroth is intended for:

* authorized security testing
* research environments
* educational use
* laboratory simulations
* red team exercises
* CTF environments

Users are solely responsible for complying with all applicable laws and regulations.

---

# License

MIT License

---

# Acknowledgements

Special thanks to:

* HackTricks
* The offensive security community
* Ollama
* Anthropic
* MCP ecosystem contributors
* Open-source security researchers

HackTricks is the primary knowledge source used to generate the local offensive knowledge graph and semantic retrieval database.

```
```
