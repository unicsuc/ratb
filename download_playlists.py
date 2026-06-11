import os
import re
import sys
import time
import json
import hashlib
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

USER_AGENT = "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3"
TIMEOUT = 8

def normalize_mac(mac: str) -> str:
    """Normalize MAC formatting to XX:XX:XX:XX:XX:XX."""
    if not isinstance(mac, str):
        return ""
    hex_value = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(hex_value) != 12:
        return ""
    return ":".join(hex_value[i:i+2] for i in range(0, 12, 2)).upper()

def build_device_identity(mac: str) -> dict:
    """Generate stb serial number and device IDs from MAC address."""
    serialnumber = hashlib.md5(mac.encode()).hexdigest().upper()
    sn = serialnumber[0:13]
    device_id = hashlib.sha256(sn.encode()).hexdigest().upper()
    device_id2 = hashlib.sha256(mac.encode()).hexdigest().upper()
    hw_version_2 = hashlib.sha1(mac.encode()).hexdigest()
    return {
        "sn": sn,
        "device_id": device_id,
        "device_id2": device_id2,
        "adid": hw_version_2,
    }

def sanitize_filename(name: str) -> str:
    """Sanitize the server name to use as a filename."""
    name = re.sub(r'[\\/*?:"<>|]', "", name)
    name = name.replace(" ", "_")
    return name.lower()

def try_download_playlist(portal_url: str, mac: str, stop_event: threading.Event) -> tuple[bool, str | None]:
    """Test Stalker portal MAC address and return the M3U content if valid and has channels."""
    if stop_event.is_set():
        return False, None

    portal_url = portal_url.rstrip('/')
    if not portal_url.startswith(('http://', 'https://')):
        portal_url = 'http://' + portal_url

    normalized_mac = normalize_mac(mac)
    if not normalized_mac:
        return False, None

    identity = build_device_identity(normalized_mac)
    session = requests.Session()

    # Configure session retries
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    try:
        # Step 1: Handshake
        if stop_event.is_set():
            return False, None

        handshake_url = f"{portal_url}/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml"
        cookies = {
            "mac": normalized_mac,
            "stb_lang": "en",
            "timezone": "America/Los_Angeles",
            "sn": identity["sn"],
            "device_id": identity["device_id"],
            "device_id2": identity["device_id2"],
            "adid": identity["adid"],
            "hw_version": "1.7-BD-00",
        }

        resp = session.get(
            handshake_url,
            headers={"User-Agent": USER_AGENT},
            cookies=cookies,
            params={"token": ""},
            timeout=TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()

        js_data = data.get("js", {})
        token = js_data.get("token")
        random_value = js_data.get("random") or "0"

        if not token:
            return False, None

        session.cookies.set("mac", normalized_mac)
        session.cookies.set("token", token)

        # Step 2: Profile signature auth (MAG device emulation signature)
        if stop_event.is_set():
            return False, None

        sig = hashlib.sha256(str(random_value).encode()).hexdigest().upper()
        profile_url = f"{portal_url}/portal.php?type=stb&action=get_profile&JsHttpRequest=1-xml"
        
        profile_params = {
            "hd": "1",
            "ver": "ImageDescription: 0.2.18-r23-250; ImageDate: Wed Aug 29 10:49:53 EEST 2018; PORTAL version: 5.3.1; API Version: JS API version: 343; STB API version: 146; Player Engine version: 0x58c",
            "num_banks": "2",
            "sn": identity["sn"],
            "stb_type": "MAG250",
            "client_type": "STB",
            "image_version": "218",
            "video_out": "hdmi",
            "device_id": identity["device_id"],
            "device_id2": identity["device_id2"],
            "sig": sig,
            "auth_second_step": "1",
            "hw_version": "1.7-BD-00",
            "not_valid_token": "0",
            "timestamp": str(round(time.time())),
            "api_sig": "262",
            "prehash": "0",
        }

        profile_cookies = {
            "mac": normalized_mac,
            "token": token,
            "sn": identity["sn"],
            "device_id": identity["device_id"],
            "device_id2": identity["device_id2"],
        }

        try:
            session.get(
                profile_url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Authorization": f"Bearer {token}",
                    "X-Random": str(random_value) if random_value and random_value != "0" else ""
                },
                cookies=profile_cookies,
                params=profile_params,
                timeout=TIMEOUT
            )
        except Exception:
            # Continue even if profile call fails (some portals are less strict)
            pass

        # Step 3: Fetch genres
        if stop_event.is_set():
            return False, None

        genres_url = f"{portal_url}/server/load.php?type=itv&action=get_genres"
        resp = session.get(
            genres_url,
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": f"Bearer {token}"
            },
            timeout=TIMEOUT
        )
        resp.raise_for_status()
        genres_data = resp.json().get("js", [])

        genres = {}
        if isinstance(genres_data, list):
            for genre in genres_data:
                if isinstance(genre, dict):
                    gid = genre.get("id")
                    gtitle = genre.get("title") or genre.get("name", "Unknown")
                    if gid:
                        genres[str(gid)] = gtitle

        # Step 4: Fetch channels
        if stop_event.is_set():
            return False, None

        channels_url = f"{portal_url}/portal.php?type=itv&action=get_all_channels"
        resp = session.get(
            channels_url,
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": f"Bearer {token}"
            },
            timeout=TIMEOUT
        )
        resp.raise_for_status()
        channels = resp.json().get("js", {}).get("data", [])

        if not channels or not isinstance(channels, list):
            return False, None

        # Step 5: Format to M3U
        m3u_lines = ["#EXTM3U"]
        for channel in channels:
            if not isinstance(channel, dict):
                continue
            name = channel.get("name", "Unknown")
            cmd = channel.get("cmd", "")
            logo = channel.get("logo", "")
            genre_id = str(channel.get("tv_genre_id", ""))
            channel_id = channel.get("id", "")

            genre_name = genres.get(genre_id, "Uncategorized")
            stream_url = None

            if cmd:
                if cmd.startswith("ffmpeg "):
                    cmd = cmd.replace("ffmpeg ", "", 1)

                if "http:/localhost" in cmd or "localhost" in cmd:
                    match = re.search(r'/ch/(\d+)', cmd)
                    if match:
                        stream_id = match.group(1)
                        stream_url = f"{portal_url}/play/live.php?mac={normalized_mac}&stream={stream_id}&extension=ts"
                    else:
                        if channel_id:
                            stream_url = f"{portal_url}/play/live.php?mac={normalized_mac}&stream={channel_id}&extension=ts"
                elif cmd.endswith("_") and "/ch/" in cmd:
                    match = re.search(r'/ch/(\d+)', cmd)
                    if match:
                        stream_id = match.group(1)
                        stream_url = f"{portal_url}/play/live.php?mac={normalized_mac}&stream={stream_id}&extension=ts"

                if not stream_url:
                    stream_url = cmd

            if not stream_url and channel_id:
                stream_url = f"{portal_url}/play/live.php?mac={normalized_mac}&stream={channel_id}&extension=ts"

            if not stream_url:
                continue

            extinf_parts = ["#EXTINF:-1"]
            if genre_name:
                extinf_parts.append(f'group-title="{genre_name}"')
            if logo:
                extinf_parts.append(f'tvg-logo="{logo}"')
            if channel_id:
                extinf_parts.append(f'tvg-id="{channel_id}"')

            extinf_line = " ".join(extinf_parts) + f",{name}"
            m3u_lines.append(extinf_line)
            m3u_lines.append(stream_url)

        return True, "\n".join(m3u_lines)

    except Exception:
        return False, None

def process_server(server: dict, output_dir: str, max_threads_per_server: int) -> bool:
    """Find a working MAC for the server, download M3U, and save it."""
    server_name = server.get("name", "Unknown Server")
    portal_url = server.get("portal_url", "")
    macs = server.get("macs", [])

    if not portal_url or not macs:
        print(f"[-] Server '{server_name}' has no URL or MAC addresses. Skipping.")
        return False

    print(f"\n[*] Server: {server_name} | URL: {portal_url}")
    print(f"[*] Testing {len(macs)} MAC addresses with concurrency...")

    stop_event = threading.Event()
    m3u_content = None
    successful_mac = None

    workers = min(max_threads_per_server, len(macs))
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_mac = {
            executor.submit(try_download_playlist, portal_url, mac, stop_event): mac 
            for mac in macs
        }

        for future in as_completed(future_to_mac):
            mac = future_to_mac[future]
            try:
                success, content = future.result()
                if success and content:
                    m3u_content = content
                    successful_mac = mac
                    stop_event.set()  # Signal other threads to stop
                    break
            except Exception:
                pass

    if m3u_content:
        # Save M3U to output directory
        sanitized_name = sanitize_filename(server_name)
        filename = f"{sanitized_name}.m3u"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(m3u_content)
            
        print(f"[+] SUCCESS: Saved '{filename}' ({len(m3u_content.splitlines()) // 2} channels) using MAC {successful_mac}")
        return True
    else:
        print(f"[-] FAILED: No working MAC address found for '{server_name}'")
        return False

def main():
    parser = argparse.ArgumentParser(description="Download Stalker IPTV M3U Playlists")
    parser.add_argument("--url", default="https://raw.githubusercontent.com/staycanuca/hub/main/_tools/servers.json", 
                        help="URL of the servers.json config file")
    parser.add_argument("--output", default="playlists", help="Directory where M3U files should be saved")
    parser.add_argument("--threads", type=int, default=10, help="Max parallel MAC tests per server")
    args = parser.parse_args()

    # Ensure output directory exists
    os.makedirs(args.output, exist_ok=True)

    print("======================================================")
    print("           STALKER PORTAL M3U PLAYLIST DOWNLOADER      ")
    print("======================================================")
    print(f"[*] Fetching server config from: {args.url}")

    try:
        resp = requests.get(args.url, timeout=15)
        resp.raise_for_status()
        config_data = resp.json()
    except Exception as e:
        print(f"[!] Critical Error: Failed to fetch servers JSON: {e}")
        sys.exit(1)

    servers = config_data.get("servers", [])
    if not servers:
        print("[!] Error: No servers found in the JSON configuration.")
        sys.exit(1)

    print(f"[+] Loaded {len(servers)} servers from configuration.")

    success_count = 0
    start_time = time.time()

    # Process each server sequentially, testing its MACs in parallel
    for server in servers:
        if process_server(server, args.output, args.threads):
            success_count += 1

    elapsed = time.time() - start_time
    print("\n======================================================")
    print("                    DOWNLOAD SUMMARY                  ")
    print("======================================================")
    print(f"[*] Time elapsed: {elapsed:.2f} seconds")
    print(f"[*] Successfully downloaded: {success_count} / {len(servers)} playlists")
    print(f"[*] Saved to directory: {os.path.abspath(args.output)}")
    print("======================================================")

if __name__ == "__main__":
    main()
