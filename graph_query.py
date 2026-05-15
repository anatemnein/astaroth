#!/usr/bin/env python3

import json
import sys
from pathlib import Path

BRAIN = Path.home() / "astaroth" / "brain"

NODES_DIR = BRAIN / "graph" / "nodes"
EDGES_FILE = BRAIN / "graph" / "edges.json"


# =========================
# LOAD
# =========================

def load_nodes():

    nodes = {}

    for path in NODES_DIR.glob("*.json"):

        try:
            data = json.loads(path.read_text())
            nodes[data["id"]] = data
        except Exception:
            continue

    return nodes


def load_edges():

    try:
        return json.loads(EDGES_FILE.read_text())
    except Exception:
        return []


# =========================
# SEARCH
# =========================

def search_nodes(nodes, query):

    query = query.lower()

    matches = []

    for node_id, node in nodes.items():

        blob = json.dumps(node).lower()

        if query in blob:
            matches.append(node)

    return matches


# =========================
# GRAPH
# =========================

def related_edges(edges, node_id):

    rel = []

    for edge in edges:

        if edge["from"] == node_id:
            rel.append(edge)

    return rel


def reverse_edges(edges, node_id):

    rel = []

    for edge in edges:

        if edge["to"] == node_id:
            rel.append(edge)

    return rel


# =========================
# DISPLAY
# =========================

def print_node(node):

    print("=" * 80)

    print(f"[NODE]")
    print(f"Name        : {node.get('name')}")
    print(f"Type        : {node.get('type')}")

    print(f"\nDomains:")
    for d in node.get("domains", []):
        print(f"  - {d}")

    print(f"\nPrimitives:")
    for p in node.get("primitives", []):
        print(f"  - {p}")

    print(f"\nLeads To:")
    for l in node.get("leads_to", []):
        print(f"  - {l}")

    print(f"\nRelated Tools:")
    for t in node.get("related_tools", []):
        print(f"  - {t}")

    print(f"\nConditions:")
    for c in node.get("conditions", [])[:5]:
        print(f"  - {c}")

    print(f"\nActions:")
    for a in node.get("actions", [])[:8]:
        print(f"  - {a}")


def print_edges(edges):

    if not edges:
        return

    print(f"\n[GRAPH RELATIONS]")

    for e in edges[:20]:

        reason = e.get("reason", "")

        print(
            f"  {e['from']} "
            f"--[{e['type']}]--> "
            f"{e['to']}"
        )

        if reason:
            print(f"      ↳ {reason}")


# =========================
# ATTACK PATHS
# =========================

def attack_paths(edges, start):

    paths = []

    for e in edges:

        if e["from"] == start:

            current = [start, e["to"]]

            nxt = e["to"]

            for e2 in edges:

                if e2["from"] == nxt:
                    current.append(e2["to"])

            paths.append(current)

    return paths


def print_paths(paths):

    if not paths:
        return

    print(f"\n[ATTACK PATHS]")

    for p in paths[:10]:

        print("  " + "  →  ".join(p))


# =========================
# MAIN
# =========================

def main():

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python graph_query.py <query>")
        sys.exit(1)

    query = " ".join(sys.argv[1:])

    nodes = load_nodes()

    edges = load_edges()

    matches = search_nodes(nodes, query)

    if not matches:
        print("[-] No matching nodes")
        sys.exit(0)

    print(f"[+] Matches: {len(matches)}")

    for node in matches[:5]:

        print_node(node)

        node_edges = related_edges(
            edges,
            node["id"]
        )

        print_edges(node_edges)

        paths = attack_paths(
            edges,
            node["id"]
        )

        print_paths(paths)

        print()


if __name__ == "__main__":
    main()
