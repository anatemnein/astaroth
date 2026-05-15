# Astaroth

> Offensive Security Copilot powered by MCP, RAG, Knowledge Graphs, and Local LLMs.

Astaroth is a local-first offensive security assistant designed for:

* Red Team operations
* Active Directory assessments
* Cloud security testing
* Infrastructure exploitation
* CTFs and labs
* Tool output analysis
* Attack path reasoning

Instead of acting like a generic chatbot, Astaroth behaves like an operator support system.

It combines:

* MCP (Model Context Protocol)
* Semantic RAG retrieval
* Knowledge graph traversal
* Local LLM inference
* Attack chain reasoning
* Operational context expansion

---

# Features

## MCP Offensive Consultant

Astaroth exposes an MCP server that can be consumed by:

* OpenClaude
* Claude Desktop
* OpenWebUI
* Custom agent frameworks
* LangGraph
* Local copilots

The MCP layer provides:

* consultation
* attack path reasoning
* tool output interpretation
* next-step planning
* semantic retrieval
* graph expansion

---

## Semantic RAG Engine

The project ingests HackTricks and converts it into searchable embeddings.

Capabilities:

* semantic search
* context-aware retrieval
* technique correlation
* infrastructure-focused knowledge lookup

---

## Knowledge Graph Brain

Astaroth automatically generates graph nodes and edges from offensive security documentation.

The graph contains:

* techniques
* primitives
* attack paths
* credentials abuse chains
* cloud escalation paths
* AD escalation paths
* post-exploitation relationships

This allows future reasoning such as:

```text
ESC4
→ certificate abuse
→ PKINIT
→ TGT
→ DCSync
```

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

## Recommended

* Linux
* Python 3.11+
* Ollama
* NVIDIA GPU (optional)

---

# Installation

## Clone repository

```bash
git clone https://github.com/YOURUSER/astaroth.git
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

## Install Ollama

[https://ollama.com](https://ollama.com)

Pull recommended models:

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama pull nomic-embed-text
```

---

# Setup Knowledge Sources

Clone HackTricks:

```bash
git clone https://github.com/HackTricks-wiki/hacktricks.git
```

Create symlink:

```bash
mkdir -p brain/sources
ln -s ~/astaroth/hacktricks brain/sources/hacktricks
```

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

---

# Important Notes

Astaroth is intended for:

* authorized security testing
* labs
* research environments
* CTFs
* red team simulations

Users are responsible for complying with all applicable laws and regulations.

---

# License

MIT License

---

# Acknowledgements

* HackTricks
* Ollama
* MCP ecosystem
* OpenClaude
* Offensive security community
