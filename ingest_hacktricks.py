#!/usr/bin/env python3
import os
import re
import sys
import json
import hashlib
import sqlite3
import requests
from pathlib import Path

BASE_DIR = Path(os.getenv("HACKTRICKS_SRC", str(Path(__file__).parent / "hacktricks" / "src")))
DB_PATH = os.getenv("HACKTRICKS_DB", str(Path(__file__).parent / "hacktricks_rag.db"))
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
OLLAMA_URL = os.getenv("OLLAMA_EMBED_URL", "http://localhost:11434/api/embed")


def embed(text: str) -> list[float]:
    r = requests.post(OLLAMA_URL, json={
        "model": EMBED_MODEL,
        "input": text[:6000]
    }, timeout=120)
    r.raise_for_status()
    return r.json()["embeddings"][0]


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


def content_hash(path: str, title: str, text: str) -> str:
    return hashlib.sha256(f"{path}:{title}:{text}".encode()).hexdigest()[:20]


def init_db(conn: sqlite3.Connection, rebuild: bool) -> None:
    cur = conn.cursor()

    if rebuild:
        cur.execute("DROP TABLE IF EXISTS chunks")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chunks (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            path      TEXT,
            title     TEXT,
            text      TEXT,
            embedding TEXT,
            hash      TEXT UNIQUE
        )
    """)

    # add hash column if upgrading from old schema without it
    try:
        cur.execute("ALTER TABLE chunks ADD COLUMN hash TEXT UNIQUE")
    except sqlite3.OperationalError:
        pass

    conn.commit()


def main(rebuild: bool = False) -> None:
    conn = sqlite3.connect(DB_PATH)
    init_db(conn, rebuild)
    cur = conn.cursor()

    files = list(BASE_DIR.rglob("*.md"))
    print(f"[+] Source: {BASE_DIR}")
    print(f"[+] Found {len(files)} markdown files")
    print(f"[+] Mode: {'full rebuild' if rebuild else 'incremental (skipping already-indexed chunks)'}")

    added = 0
    skipped = 0

    for idx, path in enumerate(files, 1):
        chunks = chunk_markdown(path)
        if not chunks:
            continue

        file_added = 0
        for ch in chunks:
            h = content_hash(ch["path"], ch["title"], ch["text"])

            cur.execute("SELECT 1 FROM chunks WHERE hash = ?", (h,))
            if cur.fetchone():
                skipped += 1
                continue

            vector = embed(ch["text"])
            cur.execute(
                "INSERT OR IGNORE INTO chunks (path, title, text, embedding, hash) VALUES (?, ?, ?, ?, ?)",
                (ch["path"], ch["title"], ch["text"], json.dumps(vector), h)
            )
            added += 1
            file_added += 1

        if file_added:
            print(f"[{idx}/{len(files)}] {path.name} (+{file_added})")
            conn.commit()

    conn.close()
    print(f"[+] Done — added: {added}, skipped (already indexed): {skipped}")
    print(f"[+] DB: {DB_PATH}")


if __name__ == "__main__":
    rebuild = "--rebuild" in sys.argv
    main(rebuild=rebuild)
