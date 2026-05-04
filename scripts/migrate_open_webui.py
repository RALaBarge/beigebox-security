#!/usr/bin/env python3
"""
Import existing Open WebUI conversation history into BeigeBox.

DEPRECATED 2026-05-04: This script targeted the legacy SQLiteStore + ChromaDB
storage stack. Both have been removed:
  - SQLiteStore was decomposed into per-entity repos in batch B (April 2026).
  - ChromaDB was removed in favor of PostgreSQL + pgvector on 2026-05-04.

The script is preserved as read-only history. To resurrect it, port the
write path to use:
  - `beigebox.storage.repos.make_conversation_repo(db)` for messages,
  - `beigebox.storage.backends.make_backend("postgres", connection_string=...)`
    plus `VectorStore(backend=..., embedding_model=..., embedding_url=...)`
    for embeddings.

Original usage (no longer functional):
    python scripts/migrate_open_webui.py --source ~/.config/open-webui/webui.db
    python scripts/migrate_open_webui.py --source /path/to/webui.db --dry-run
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def read_open_webui_db(db_path: str) -> list[dict]:
    """
    Read conversations from Open WebUI's SQLite database.
    Open WebUI stores chats as JSON blobs in a 'chat' table.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute("SELECT id, chat, created_at, updated_at FROM chat ORDER BY created_at").fetchall()
    except sqlite3.OperationalError:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print(f"Could not find 'chat' table. Available tables: {[t['name'] for t in tables]}")
        conn.close()
        return []

    conversations = []
    for row in rows:
        try:
            chat_data = json.loads(row["chat"]) if isinstance(row["chat"], str) else row["chat"]
            conversations.append({
                "id": row["id"],
                "chat": chat_data,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })
        except (json.JSONDecodeError, TypeError) as e:
            print(f"  Skipping conversation {row['id']}: {e}")

    conn.close()
    return conversations


def extract_messages(chat_data: dict) -> list[dict]:
    """Extract messages from Open WebUI's chat JSON structure."""
    messages = []
    raw_messages = None

    if isinstance(chat_data, dict):
        if "messages" in chat_data:
            raw_messages = chat_data["messages"]
        elif "history" in chat_data and isinstance(chat_data["history"], dict):
            if "messages" in chat_data["history"]:
                raw_messages = chat_data["history"]["messages"]

    if not raw_messages:
        return messages

    if isinstance(raw_messages, dict):
        raw_messages = list(raw_messages.values())

    for msg in raw_messages:
        if isinstance(msg, dict):
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role and content:
                messages.append({
                    "role": role,
                    "content": content,
                    "model": msg.get("model", chat_data.get("model", "")),
                    "timestamp": msg.get("timestamp", ""),
                })

    return messages


def main():
    parser = argparse.ArgumentParser(description="Import Open WebUI history (DEPRECATED)")
    parser.add_argument("--source", "-s", required=True, help="Path to Open WebUI webui.db")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be imported without writing")
    args = parser.parse_args()

    source = Path(args.source)
    if not source.exists():
        print(f"Source database not found: {source}")
        sys.exit(1)

    print(f"Reading Open WebUI database: {source}")
    conversations = read_open_webui_db(str(source))
    print(f"Found {len(conversations)} conversations")

    total_messages = 0
    for conv in conversations:
        msgs = extract_messages(conv["chat"])
        total_messages += len(msgs)

    print(f"Total messages to import: {total_messages}")

    if args.dry_run:
        print("\n[DRY RUN] No data written. Remove --dry-run to import.")
        for conv in conversations[:5]:
            msgs = extract_messages(conv["chat"])
            print(f"  Conv {conv['id'][:12]}...: {len(msgs)} messages")
        if len(conversations) > 5:
            print(f"  ... and {len(conversations) - 5} more")
        return

    print(
        "\nERROR: This script is deprecated. The SQLiteStore and ChromaDB write\n"
        "       paths it depended on were removed from BeigeBox. See the module\n"
        "       docstring for a migration plan that targets the current\n"
        "       per-entity repos + PostgreSQL + pgvector stack."
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
