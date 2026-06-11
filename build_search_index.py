#!/usr/bin/env python3
"""Build the static HubLive playlist search index and its remote manifest."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


SCHEMA_VERSION = "2-standard-sqlite"
STREAM_RE = re.compile(r"[?&]stream=(\d+)")
PLAYLIST_RE = re.compile(r"server_(\d+)\.m3u", re.IGNORECASE)
SERVER_NAME_RE = re.compile(r"^Server\s+(\d+)(?:\s+.*)?$", re.IGNORECASE)


def load_json(source):
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "HubLive-Search-Index-Builder"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    with open(source, "r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_portal(url):
    parsed = urlparse((url or "").strip())
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    port = parsed.port
    if port in (None, 80) and parsed.scheme.lower() == "http":
        return host
    if port in (None, 443) and parsed.scheme.lower() == "https":
        return host
    return f"{host}:{port}" if port else host


def portal_host(url):
    return (urlparse((url or "").strip()).hostname or "").lower()


def git_blob_sha(content):
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_commit(repo_root):
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return os.environ.get("GITHUB_SHA", "")


def load_servers(source):
    payload = load_json(source)
    servers = payload.get("servers", payload) if isinstance(payload, dict) else payload
    if not isinstance(servers, list):
        raise ValueError("Servers JSON must contain a list or a 'servers' list.")

    by_number = {}
    for server in servers:
        match = SERVER_NAME_RE.match((server.get("name") or "").strip())
        if not match:
            continue
        number = int(match.group(1))
        if number in by_number:
            raise ValueError(f"Duplicate server number in servers JSON: {number}")
        by_number[number] = server
    return by_number


def create_schema(connection):
    connection.executescript(
        """
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        CREATE TABLE channels(
            name TEXT NOT NULL,
            name_search TEXT NOT NULL,
            playlist TEXT NOT NULL,
            stream_id TEXT NOT NULL
        );
        CREATE INDEX idx_channels_playlist ON channels(playlist);
        CREATE TABLE playlist_metadata(
            playlist TEXT PRIMARY KEY,
            server_id TEXT NOT NULL,
            server_name TEXT NOT NULL,
            portal_url TEXT NOT NULL,
            portal_key TEXT NOT NULL,
            blob_sha TEXT NOT NULL
        );
        CREATE TABLE build_metadata(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )


def first_stream_host(text):
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(("http://", "https://")):
            return portal_host(line)
    return ""


def insert_playlist(connection, playlist, content):
    rows = []
    inserted = 0
    pending = None
    text = content.decode("utf-8", errors="ignore")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("#EXTINF"):
            pending = line
            continue
        if not pending or not line or line.startswith("#"):
            continue

        stream_match = STREAM_RE.search(line)
        if stream_match:
            name = pending.rsplit(",", 1)[-1].strip()
            rows.append(
                (
                    name,
                    " ".join(name.casefold().split()),
                    playlist,
                    stream_match.group(1),
                )
            )
        pending = None

        if len(rows) >= 10000:
            connection.executemany("INSERT INTO channels VALUES(?,?,?,?)", rows)
            inserted += len(rows)
            rows = []

    if rows:
        connection.executemany("INSERT INTO channels VALUES(?,?,?,?)", rows)
        inserted += len(rows)
    return inserted


def build_index(playlists_dir, servers_source, output_dir, archive_url):
    playlists_dir = Path(playlists_dir).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    servers = load_servers(servers_source)
    playlist_paths = sorted(
        playlists_dir.glob("server_*.m3u"),
        key=lambda path: int(PLAYLIST_RE.fullmatch(path.name).group(1)),
    )
    if not playlist_paths:
        raise RuntimeError(f"No server_*.m3u files found in {playlists_dir}")

    archive_path = output_dir / "playlist_search.db.zip"
    manifest_path = output_dir / "manifest.json"

    with tempfile.TemporaryDirectory(
        prefix=".hublive-index-",
        dir=output_dir,
    ) as temp_dir:
        temp_database = Path(temp_dir) / "playlist_search.db"
        connection = sqlite3.connect(temp_database)
        create_schema(connection)
        channel_count = 0
        playlist_count = 0
        skipped = []

        try:
            for playlist_path in playlist_paths:
                match = PLAYLIST_RE.fullmatch(playlist_path.name)
                server_number = int(match.group(1))
                server = servers.get(server_number)
                if not server:
                    skipped.append(f"{playlist_path.name}: missing server metadata")
                    continue

                content = playlist_path.read_bytes()
                stream_host = first_stream_host(
                    content.decode("utf-8", errors="ignore")
                )
                server_host = portal_host(server.get("portal_url"))
                if not stream_host or stream_host != server_host:
                    skipped.append(
                        f"{playlist_path.name}: stream host {stream_host!r} "
                        f"does not match server host {server_host!r}"
                    )
                    continue

                inserted = insert_playlist(connection, playlist_path.name, content)
                if not inserted:
                    skipped.append(f"{playlist_path.name}: no searchable channels")
                    continue

                portal_url = (server.get("portal_url") or "").rstrip("/")
                connection.execute(
                    "INSERT INTO playlist_metadata VALUES(?,?,?,?,?,?)",
                    (
                        playlist_path.name,
                        server.get("id") or "",
                        server.get("name") or "",
                        portal_url,
                        normalize_portal(portal_url),
                        git_blob_sha(content),
                    ),
                )
                channel_count += inserted
                playlist_count += 1
                print(f"Indexed {playlist_path.name}: {inserted} channels")

            metadata = {
                "schema_version": SCHEMA_VERSION,
                "channel_count": str(channel_count),
                "playlist_count": str(playlist_count),
                "repo_commit": repo_commit(playlists_dir.parent),
            }
            connection.executemany(
                "INSERT INTO build_metadata VALUES(?,?)",
                metadata.items(),
            )
            connection.commit()
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise RuntimeError("SQLite integrity_check failed.")
        finally:
            connection.close()

        if not playlist_count or not channel_count:
            raise RuntimeError("The generated index is empty.")

        temp_archive = Path(temp_dir) / archive_path.name
        with zipfile.ZipFile(
            temp_archive,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            archive.write(temp_database, "playlist_search.db")

        archive_sha256 = sha256_file(temp_archive)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "repo_commit": metadata["repo_commit"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "playlist_count": playlist_count,
            "channel_count": channel_count,
            "archive": archive_path.name,
            "archive_url": archive_url,
            "archive_size": temp_archive.stat().st_size,
            "archive_sha256": archive_sha256,
        }
        temp_manifest = Path(temp_dir) / manifest_path.name
        temp_manifest.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        os.replace(temp_archive, archive_path)
        os.replace(temp_manifest, manifest_path)

    for message in skipped:
        print(f"Skipped: {message}")
    print(
        f"Built {playlist_count} playlists, {channel_count} channels, "
        f"SHA-256 {archive_sha256}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Build HubLive's static SQLite playlist search index."
    )
    parser.add_argument("--playlists", default="playlists")
    parser.add_argument("--servers", required=True, help="servers.json path or URL")
    parser.add_argument("--output", default="search-index")
    parser.add_argument(
        "--archive-url",
        default=(
            "https://raw.githubusercontent.com/unicsuc/ratb/main/"
            "search-index/playlist_search.db.zip"
        ),
    )
    args = parser.parse_args()
    build_index(args.playlists, args.servers, args.output, args.archive_url)


if __name__ == "__main__":
    main()
