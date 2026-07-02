import requests

def fetch_latest_version(library_name: str) -> str | None:
    try:
        url = f"https://proxy.golang.org/{library_name}/@latest"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json().get("Version")
    except Exception:
        return None