# pr_creation.py
import os
import logging
import subprocess
import tempfile
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse
from github import Github, GithubException
from dementor_sca.llm_client import chat as _llm_chat

# --- Custom Exception for HTTP Errors (moved here as it's used by functions in this script) ---
class HTTPException(Exception):
    """Custom exception for HTTP-related errors."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(self.detail)

# --- Constants for PR Creation ---
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
GITHUB_API_DELAY = 1  # seconds between API calls
BRANCH_NAME_MAX_LENGTH = 200

# --- URL Validation Helper (moved here as it's used by functions in this script) ---
def validate_git_url(url: str) -> bool:
    """Validates that a URL is properly formatted for Git operations."""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

# --- Helper Functions for PR Creation ---
def get_current_timestamp() -> Dict[str, str]:
    """Returns formatted timestamps for branches and PRs."""
    now = datetime.now()
    return {
        "branch": now.strftime("%Y%m%d%H%M"),
        "pr": now.strftime("%Y-%m-%d %H:%M")
    }

def clean_llm_output(content: str) -> str:
    """Cleans LLM output to remove conversational text or markdown fences."""
    lines = [line for line in content.splitlines()
            if not line.strip().startswith(('Here is', '---', '```'))]
    return "\n".join(lines).strip()

def github_retry(func, *args, **kwargs):
    """Retries GitHub API calls with exponential backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            time.sleep(GITHUB_API_DELAY)
            return func(*args, **kwargs)
        except GithubException as ge:
            logging.warning(f"GitHub API error (attempt {attempt+1}/{MAX_RETRIES}): {ge.status} - {ge.data.get('message', 'No message')}")
            if ge.status in [409, 502] and attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            raise

# --- Core Functionality for PR Creation ---
def rewrite_file_content_with_llm(file_path: str, content: str, lib: str, new_ver: str, _model: str = None) -> str:
    """
    Uses LLM to update dependency versions in file content.
    Prompts the LLM to only change the specific library's version,
    preserve formatting, and return only the file content.
    """
    prompt = f"""Update {lib} to {new_ver} in this file. Rules:
    1. Only change {lib}'s version
    2. Preserve all formatting
    3. Return only file content

    File: {file_path}
    Content:
    {content}"""

    try:
        result = _llm_chat(prompt)
        return clean_llm_output(result)
    except Exception as e:
        logging.error(f"LLM failed during rewrite for {file_path}: {str(e)}")
        raise

def create_pr_with_llm_update(
    github_token: str,
    repo_owner: str, repo_name: str, library_name: str,
    file_path: str, current_ver: str, new_ver: str,
    ollama_model: str = None,  # ignored — kept for call-site backward compat
) -> str:
    """
    Clones a repository, uses LLM to update a dependency, commits the change
    to a new branch, and creates a Pull Request on GitHub.
    """
    timestamp = get_current_timestamp()
    safe_lib = library_name.replace('/', '-').replace('.', '-')
    branch_name = (
        f"fix/upgrade-{safe_lib}-to-{new_ver.replace('.', '-')}-{timestamp['branch']}"
    )[:BRANCH_NAME_MAX_LENGTH]

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Clone repo
        repo_path_local = os.path.join(tmp_dir, repo_name)
        logging.info(f"Cloning {repo_owner}/{repo_name} to {repo_path_local} for PR creation...")

        # Prepare environment for subprocess to force IPv4 and increase verbosity for debugging
        clone_env = os.environ.copy()
        clone_env['GIT_CURL_IP_RESOLVE'] = 'ipv4'
        clone_env['GIT_CURL_VERBOSE'] = '1'
        clone_env['GIT_TRACE'] = '1'

        # Corrected URL construction for cloning with token.
        clone_url = f"https://{github_token}@[github.com/](https://github.com/){repo_owner}/{repo_name}.git"
        if not validate_git_url(clone_url):
            raise HTTPException(status_code=400, detail=f"Invalid Git URL format: {clone_url}")

        logging.info(f"DEBUG: create_pr_with_llm_update attempting to clone with URL: {clone_url.replace(github_token, '***TOKEN_REDACTED***')}")

        try:
            subprocess.run(
                ["git", "clone", "--depth=1", clone_url, repo_path_local],
                check=True, timeout=300, capture_output=True, text=True,
                env=clone_env
            )
            logging.info(f"Successfully cloned {repo_name}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Clone failed for {repo_owner}/{repo_name}: Stderr: {e.stderr}, Stdout: {e.stdout}")
            raise HTTPException(status_code=500, detail=f"Failed to clone repository: {e.stderr.strip()}")
        except subprocess.TimeoutExpired:
            logging.error(f"Clone timed out for {repo_owner}/{repo_name}.")
            raise HTTPException(status_code=500, detail="Repository clone timed out.")
        except Exception as e:
            logging.error(f"Unexpected error during clone for {repo_owner}/{repo_name}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Unexpected error during clone: {str(e)}")

        # Process file
        local_file = os.path.join(repo_path_local, file_path)
        if not os.path.exists(local_file):
            logging.error(f"File not found in cloned repo: {local_file}")
            raise HTTPException(status_code=404, detail=f"File '{file_path}' not found in repository.")

        with open(local_file, 'r', encoding='utf-8') as f:
            original = f.read()

        logging.info(f"Rewriting content for {file_path} using LLM...")
        updated = rewrite_file_content_with_llm(file_path, original, library_name, new_ver)

        if updated.strip() == original.strip():
            logging.warning(f"No changes detected for {library_name} in {file_path}. Skipping PR.")
            raise ValueError("No changes detected in the file after LLM rewrite.")

        # GitHub operations
        g = Github(github_token)
        repo = github_retry(g.get_repo, f"{repo_owner}/{repo_name}")
        default_branch = repo.get_branch(repo.default_branch)

        try:
            file_content = github_retry(repo.get_contents, file_path, ref=default_branch.name)
        except GithubException as e:
            logging.error(f"Failed to get file content for {file_path} from default branch: {e.status} - {e.data.get('message')}")
            raise HTTPException(status_code=500, detail=f"Failed to get file content from GitHub: {e.data.get('message')}")

        # Create branch if needed
        try:
            repo.get_branch(branch_name)
            logging.info(f"Branch '{branch_name}' already exists.")
        except GithubException: # If branch doesn't exist, a GithubException is raised
            logging.info(f"Creating branch '{branch_name}'...")
            github_retry(
                repo.create_git_ref,
                ref=f"refs/heads/{branch_name}",
                sha=default_branch.commit.sha
            )
            logging.info(f"Branch '{branch_name}' created.")

        # Commit changes
        logging.info(f"Committing changes to {file_path} on branch {branch_name}...")
        try:
            github_retry(
                repo.update_file,
                path=file_path,
                message=f"chore: Upgrade {library_name} to {new_ver}",
                content=updated,
                sha=file_content.sha,
                branch=branch_name
            )
            logging.info(f"Changes committed to {branch_name}.")
        except GithubException as e:
            logging.error(f"Failed to commit changes to {file_path}: {e.status} - {e.data.get('message')}")
            raise HTTPException(status_code=500, detail=f"Failed to commit changes: {e.data.get('message')}")

        # Create or return existing PR
        logging.info(f"Checking for existing PR for branch '{branch_name}'...")
        existing_prs = list(repo.get_pulls(
            state='open',
            head=branch_name,
            base=default_branch.name
        ))
        if existing_prs:
            logging.info(f"Found existing PR: {existing_prs[0].html_url}")
            return existing_prs[0].html_url

        logging.info(f"Creating new PR for {library_name} to {new_ver}...")
        try:
            pr = repo.create_pull(
                title=f"fix: Upgrade {library_name} to {new_ver} ({timestamp['pr']})",
                body=f"""### Automated Upgrade
| Detail | Info |
|---|---|
| Library | {library_name} |
| Old Version | {current_ver} |
| New Version | {new_ver} |
| Timestamp | {timestamp['pr']} |""",
                head=branch_name,
                base=default_branch.name
            )
            logging.info(f"PR created: {pr.html_url}")
            return pr.html_url
        except GithubException as e:
            logging.error(f"Failed to create PR: {e.status} - {e.data.get('message')}")
            raise HTTPException(status_code=500, detail=f"Failed to create Pull Request: {e.data.get('message')}")

if __name__ == '__main__':
    # This block is for direct testing of pr_creation.py, typically not used when run by server.py
    # You would need to set up dummy config/env vars here for standalone execution
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    print("This script is intended to be imported and used by server.py.")
    print("To test, run server.py and use the /api/create-pr endpoint.")