#!/usr/bin/env python3
import os
import re
import json
import sqlite3
import requests
from pathlib import Path

BASE_DIR = Path("./hacktricks/src")
DB_PATH = "hacktricks_rag.db"
EMBED_MODEL = "nomic-embed-text"
OLLAMA_URL = "http://localhost:11434/api/embed"


def embed(text: str) -> list[float]:
    r = requests.post(OLLAMA_URL, json={
        "model": EMBED_MODEL,
        "input": text[:6000]
    }, timeout=120)
    r.raise_for_status()
    data = r.json()
    return data["embeddings"][0]


def clean_md(text: str) -> str:
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def chunk_markdown(path: Path) -> list[dict]:
    raw = path.read_text(errors="ignore")
    raw = clean_md(raw)

    parts = re.split(r"\n(?=#{1,3}\s)", raw)
    chunks = []

    for part in parts:
        part = part.strip()
        if len(part) < 200:
            continue

        title = part.splitlines()[0].strip("# ").strip() if part.splitlines() else path.name

        # split long sections
        max_len = 2500
        for i in range(0, len(part), max_len):
            sub = part[i:i + max_len].strip()
            if len(sub) >= 200:
                chunks.append({
                    "path": str(path),
                    "title": title,
                    "text": sub
                })

    return chunks


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS chunks")
    cur.execute("""
        CREATE TABLE chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            title TEXT,
            text TEXT,
            embedding TEXT
        )
    """)

    files = list(BASE_DIR.rglob("*.md"))
    print(f"[+] Found {len(files)} markdown files")

    total = 0

    for idx, path in enumerate(files, 1):
        chunks = chunk_markdown(path)
        if not chunks:
            continue

        print(f"[{idx}/{len(files)}] {path} ({len(chunks)} chunks)")

        for ch in chunks:
            vector = embed(ch["text"])
            cur.execute(
                "INSERT INTO chunks (path, title, text, embedding) VALUES (?, ?, ?, ?)",
                (ch["path"], ch["title"], ch["text"], json.dumps(vector))
            )
            total += 1

        conn.commit()

    conn.close()
    print(f"[+] Indexed {total} chunks into {DB_PATH}")


if __name__ == "__main__":
    main()
