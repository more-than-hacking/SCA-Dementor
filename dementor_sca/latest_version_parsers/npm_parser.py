import requests

def fetch_latest_version(library_name: str) -> str | None:
    try:
        url = f"https://registry.npmjs.org/{library_name}"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json().get("dist-tags", {}).get("latest")
    except Exception:
        return None