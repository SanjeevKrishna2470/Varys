
from datetime import datetime
import re
from github import Github, Auth
import os
from dotenv import load_dotenv
import fnmatch
from types import SimpleNamespace
import json
import typer

load_dotenv()

app=typer.Typer(add_completion=False)



Session_Store=[]


def json_writer():
    with open('scan_results.json','w') as f:
        json.dump(Session_Store,f,indent=4)


def create_vulnerability_entry(rule_id, name, file_path, risk, desc, repo_name, evidence=None):
    return {
        "rule_id": rule_id,
        "name": name,
        "file": file_path,
        "risk": risk,
        "description": desc,
        "repository": repo_name,
        "evidence": evidence, # This is the match.group() for regex
        "timestamp": datetime.now().isoformat()
    }

def load_policy(path='policy.json'):
    with open(path,"r") as f:
        return json.load(f)
    

POLICY=load_policy()
IGNORE_DIRS=set(POLICY["ignore_dirs"])
MAX_DEPTH=POLICY["max_depth"]

def load_signatures(path='signatures.json'):
    with open(path,"r") as f:
        return json.load(f)
    

VULN_DB = []
PATTERNS = []

def initialize_scanner(signatures_data):
    """
    Parses the raw JSON signatures into optimized lists and compiled regex objects.
    """
    global VULN_DB, PATTERNS
    
    # 1. Clear existing data (in case of a reload)
    VULN_DB.clear()
    PATTERNS.clear()

    # 2. Compile Vulnerability Patterns
    for p in signatures_data.get("vulnerability_patterns", []):
        try:
            VULN_DB.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "risk": p.get("risk_level", "Medium"),
                "desc": p.get("description", "No description"),
                # re.I | re.M ensures case-insensitivity and line-by-line matching
                "regex": re.compile(p["pattern"], re.I | re.M)
            })
        except re.error as e:
            print(f"⚠️ Error compiling regex for {p.get('id')}: {e}")

    # 3. Map File Signatures (Sensitive filenames)
    for s in signatures_data.get("file_signatures", []):
        targets = s.get("target_files", [])
        PATTERNS.extend(targets)

    # 4. Extract Dependency File Patterns (requirements.txt, etc.)
    for d in signatures_data.get("dependency_files", []):
        PATTERNS.extend(d.get("patterns", []))

    print(f"✅ Scanner Engine Armed: {len(VULN_DB)} pattern,len{PATTERNS} file signatures and dependency files loaded.")

# --- Execution ---
SIGNATURES_JSON = load_signatures()
initialize_scanner(SIGNATURES_JSON)




def connect_to_github(token):
    auth = Auth.Token(token)
    g = Github(auth=auth, timeout=60)
    user = g.get_user()
    print(f"Connected to GitHub as {user.login}")
    return g

@app.command()
def snapshot(repo: str = typer.Argument(...,help="Target Repository (owner/repo)"),
             token: str = typer.Option(...,help="Github Token",envvar="GITHUB_TOKEN")):
    if not token: 
        print("❌ Error: GITHUB_TOKEN not found.")
        return None
    g=connect_to_github(token)
    
    contents, repo = get_repo_files(repo,g)
    if repo:
        # FIX: Start at degree 0
        all_files = get_all_files(contents, repo, 0)
        # FIX: Added 'repo' argument
        found = find_dependencies(all_files, repo)
        check_found(found) 
        json_writer()





def get_repo_files(repo_name,g):
    try:
        target = g.get_repo(repo_name)
        contents = target.get_contents("")
        return contents,target
    except Exception as e:
        print(f"Error accessing repo: {e}")
        return [], None

def AuditFile(file_path, file_content, repo):
    issues_found = False
    if file_path=="requirements.txt":
        
        lines = file_content.split('\n')
    
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'): 
                continue
        
        # 2. Extract the library name (Clean up "Flask==1.0")
        # specific_version = line.split('==')[1] if '==' in line else "unknown" # (Optional for later)
            lib_name = line.split('==')[0].split('>=')[0].split('<')[0].strip().lower()
        
        # 3. NOW check the DB
        for entry in VULN_DB:
            if entry["id"].lower() == lib_name or entry["name"].lower() == lib_name:
                list_obj=create_vulnerability_entry(entry["id"],lib_name,file_path,entry['risk'],entry['desc'],repo.full_name)
                Session_Store.append(list_obj)
                print(f"🚨 VULNERABLE LIB: {lib_name}")
                print(f"   📂 File: {file_path}")
                print(f"   ⚠️  Risk: {entry['risk']}")
                print(f"   📝 Info: {entry['desc']}")
                print(f"   🔗 Repo: {repo.full_name}\n")
                issues_found = True
                break
    else:

        for entry in VULN_DB:
             matches=entry["regex"].finditer(file_content)
             for match in matches:
                list_obj=create_vulnerability_entry(entry["id"],entry['name'],file_path,entry['risk'],entry['desc'],repo.full_name,match.group())
                Session_Store.append(list_obj)
                print(f"🚨 VULNERABLE PATTERN: {entry['name']} ({entry['id']})")
                print(f"   📂 File: {file_path}")
                print(f"   ⚠️  Risk Level: {entry['risk']}")
                print(f"   📝 Description: {entry['desc']}")
                print(f"   🔗 Repo: {repo.full_name}\n")
                issues_found = True


            
        return issues_found 


def find_dependencies(all_files, repo):
    found = False
    for file in all_files:
        for pattern in PATTERNS:
            if fnmatch.fnmatch(file.path, pattern):
                found = True
                try:
                    # LOGIC: Check if content is already there (ContentFile) or needs downloading (Imposter)
                    if hasattr(file, "decoded_content") and file.decoded_content:
                        file_content = file.decoded_content.decode("UTF-8")
                    else:
                        print(f"--> Match: {file.path}. Downloading content...")
                        content_obj = repo.get_contents(file.path)
                        file_content = content_obj.decoded_content.decode("UTF-8")
                    AuditFile(file.path,file_content,repo)
                    # FIX: Un-indented these lines so they print for EVERY match
                    print(f"✅ Found {file.path}")
                    #print(f"   Snippet: {file_content[:200].replace(chr(10), ' ')}...\n")
                    print(file_content)
                    break # Stop checking other patterns for this same file
                    
                except Exception as e:
                    print(f"⚠️ Found {file.path} but could not read content: {e}")
                    break
    return found 

def get_all_files(contents, repo, degree=0):
    all_files = []
    
    for content_file in contents:
        if content_file.name in IGNORE_DIRS:
            print(f"🚫 Skipping ignored directory: {content_file.path}")
            continue
        if content_file.type == "dir" and degree < MAX_DEPTH:
            sub_contents = repo.get_contents(content_file.path)
            all_files.extend(get_all_files(sub_contents, repo, degree + 1))
            
        # CASE 2: Hybrid Snapshot
        elif content_file.type == "dir" and degree == MAX_DEPTH:
            print(f"⚡ Snapshotting subtree: {content_file.path}")
            try:
                tree = repo.get_git_tree(content_file.sha, recursive=True)
                if getattr(tree, 'truncated', False):
                    print(f"⚠️ WARNING: Subtree {content_file.path} is TOO BIG.")
                    print("GitHub truncated the results. Some files will be missed!")
                for element in tree.tree:
                    if element.type == "blob":
                        path_parts = element.path.split('/')
                        if any(part in IGNORE_DIRS for part in path_parts):
                            continue
                        full_path = f"{content_file.path}/{element.path}"
                        imposter_file = SimpleNamespace(
                            path=full_path, 
                            sha=element.sha, 
                            type="blob"
                        )
                        # FIX: Removed the incorrect 'found!=' line. Just append.
                        all_files.append(imposter_file)
            except Exception as e:
                print(f"Error reading tree: {e}")

        # CASE 3: Standard File
        elif content_file.type == "file":
            all_files.append(content_file)
            
    return all_files 

def print_all_files(contents, repo, degree=0):
    found = False
    for content_file in contents:
        
        # CASE 1: Dive Deeper
        if content_file.type == "dir" and degree < MAX_DEPTH:
            sub_contents = repo.get_contents(content_file.path)
            found |= print_all_files(sub_contents, repo, degree + 1)
            
        # CASE 2: Hybrid Snapshot
        elif content_file.type == "dir" and degree == MAX_DEPTH:
            print(f"⚡ Snapshotting subtree: {content_file.path}")
            try:
                tree = repo.get_git_tree(content_file.sha, recursive=True)
                if getattr(tree, 'truncated', False):
                    print(f"⚠️ WARNING: Subtree {content_file.path} is TOO BIG.")
                    print("GitHub truncated the results. Some files will be missed!")
                for element in tree.tree:
                    if element.type == "blob":
                        full_path = f"{content_file.path}/{element.path}"
                        imposter_file = SimpleNamespace(
                            path=full_path, 
                            sha=element.sha, 
                            type="blob"
                        )
                        # Process immediately
                        found |= find_dependencies([imposter_file], repo)
            except Exception as e:
                print(f"Error reading tree: {e}")

        # CASE 3: Standard File
        elif content_file.type == "file":
            found |= find_dependencies([content_file], repo)
            
    return found 

def check_found(found):
    if not found:
        print("No target files found.")

@app.command()   
def QuickScan(repo: str=typer.Argument(...,help="Target Repository (owner/repo)"),
              token:str=typer.Option(...,help="Github Token",envvar="GITHUB_TOKEN")):
    g=connect_to_github(token)
    contents, repo = get_repo_files(repo,g)
    if repo:
        # Start at degree 0
        found = print_all_files(contents, repo, 0)
        check_found(found)



def main():
    # Choose one:
    app()

print(f"Total vulnerabilities found: {len(Session_Store)}")