import tempfile
import git
import re
import os
from urllib.parse import urlparse

def clean_github_url(url):
    """Clean and validate GitHub URL"""
    try:
        # Parse the URL
        parsed = urlparse(url)
        
        # Check if it's a GitHub URL
        if 'github.com' not in parsed.netloc:
            raise ValueError("Not a valid GitHub URL")
        
        # Extract path parts
        path_parts = [p for p in parsed.path.split('/') if p]
        
        if len(path_parts) < 2:
            raise ValueError("URL must contain username and repository name")
            
        # Get username and repo name
        username = path_parts[0]
        repo_name = path_parts[1]
        
        # Construct clean URL
        clean_url = f"https://github.com/{username}/{repo_name}"
        
        return clean_url
    except Exception as e:
        raise ValueError(f"Invalid GitHub URL: {str(e)}")

def clone_repo(repo_url):
    """Clone a GitHub repository to a temporary directory"""
    temp_dir = tempfile.mkdtemp()
    try:
        # Clean and validate the URL before cloning
        clean_url = clean_github_url(repo_url)
        
        # Add .git to the URL for cloning
        if not clean_url.endswith('.git'):
            clean_url += '.git'
        
        # Clone the repository
        repo = git.Repo.clone_from(clean_url, temp_dir, depth=1)
        
        # Verify repository was cloned successfully
        if not os.path.exists(temp_dir) or not os.listdir(temp_dir):
            raise Exception("Repository clone failed - directory is empty")
            
        return temp_dir
    except git.exc.GitCommandError as e:
        if 'not found' in str(e).lower():
            raise Exception("Repository not found. Please check if the URL is correct and the repository is public.")
        raise Exception(f"Git clone failed: {str(e)}")
    except Exception as e:
        raise Exception(f"Failed to clone repository: {str(e)}")