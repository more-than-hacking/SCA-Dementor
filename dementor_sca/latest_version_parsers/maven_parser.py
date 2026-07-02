import requests

def fetch_latest_version(library_name: str) -> str | None:
    try:
        group_id, artifact_id = library_name.split(":")
        url = f"https://search.maven.org/solrsearch/select?q=g:\"{group_id}\" AND a:\"{artifact_id}\"&core=gav&rows=1&wt=json"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data["response"]["docs"][0]["v"]
    except Exception:
        return None