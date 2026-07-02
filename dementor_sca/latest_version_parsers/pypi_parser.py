import requests

def fetch_latest_version(library_name: str) -> str | None:
    try:
        url = f"https://pypi.org/pypi/{library_name}/json"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json().get("info", {}).get("version")
    except Exception:
        return None
