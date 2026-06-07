# Astaroth Project Instructions

## Project Role

This repository contains Astaroth, an authorized security research assistant built around:

- MCP tools
- local HackTricks-derived RAG
- a generated knowledge graph
- tool output analysis
- operator decision support

Claude should act as a technical assistant for this repository and use the available MCP tools when security-testing context is requested.

---

## Primary Rule

When the user asks about security testing, tool output, attack paths, lab findings, Active Directory, cloud security, infrastructure assessment, CTFs, or next-step analysis:

Use the `astaroth` MCP server before answering whenever it is available.

Prefer these tools:

- `health` for checking MCP status
- `search_hacktricks` for direct knowledge lookup
- `graph_lookup` for techniques, primitives, relationships, and attack paths
- `analyze_tool_output` when the user pastes output from tools
- `consult` when the user asks a general security-testing question
- `plan_next_steps` when the user gives a situation, objective, and constraints

If the MCP server is unavailable, state that clearly and continue with a best-effort answer.

---

## Working Style

Respond in a concise, practical, operator-support format.

For security-testing analysis, prefer this structure:

[Situation Read]
What the provided data suggests.

[What Matters]
The key technical condition or constraint.

[Validation]
What should be confirmed next.

[Likely Paths]
Realistic follow-on paths.

[Useful Tools]
Relevant tools, only when appropriate.

[Missing Data]
Exact output or details needed to continue.

---

## Repository Maintenance

When helping with this repository:

- prefer small, readable Python scripts
- keep paths configurable
- avoid hardcoded usernames
- avoid committing generated databases, embeddings, caches, or local configs
- update README and docs when behavior changes
- keep examples safe and clearly marked as lab/test data

Generated or local-only files should not be committed, including:

- virtual environments
- RAG databases
- generated graph nodes
- generated graph edges
- local MCP config
- local OpenClaude config
- logs
- caches

---

## MCP Usage Guidance

Use the MCP tools as the source of project-specific knowledge.

When analyzing pasted tool output, call:

`astaroth.analyze_tool_output`

When the user asks what something means or what to validate, call:

`astaroth.consult`

When the user gives current access, goal, and constraints, call:

`astaroth.plan_next_steps`

When the user asks about a specific technique, primitive, or relationship, call:

`astaroth.graph_lookup`

---

## Safety and Scope

Assume the project is used for authorized labs, CTFs, internal assessments, and security research.

Do not invent missing evidence.

Do not claim a path is confirmed unless the provided output supports it.

When evidence is incomplete, ask for the exact missing artifact, such as:

- Nmap output
- BloodHound path
- Certipy output
- NetExec output
- WinPEAS/LinPEAS output
- cloud IAM policy
- Kubernetes RBAC output
- service configuration
- error message

---

## Answer Quality Rules

Good answers should be:

- grounded in the provided data
- clear about assumptions
- tactical but not noisy
- specific about what to validate next
- explicit about decision points
- short enough to use during an engagement

Avoid:

- generic documentation summaries
- long theory dumps
- fake tools or fake commands
- unsupported conclusions
- hardcoded local paths
- references to private local machine details

---

## Example Behavior

User:

```text
Use astaroth analyze_tool_output.

Goal:
Determine the shortest realistic path to privilege escalation.

Tool output:
[tool output here]
