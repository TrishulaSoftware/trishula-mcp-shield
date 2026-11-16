import os, zipfile
from pathlib import Path

def create_bundle():
    base_dir = Path(r"C:\Users\trish\.gemini\antigravity\scratch\trishula-mcp-shield")
    sub_dir = Path(r"C:\Users\trish\.gemini\antigravity\scratch\mcp_shield_submission")
    sub_dir.mkdir(parents=True, exist_ok=True)
    
    zip_path = sub_dir / "trishula-mcp-shield-agensi.zip"
    tracker_zip = Path(r"C:\Users\trish\.gemini\antigravity\scratch\marketplace-tracker\submissions\trishula-mcp-shield-agensi.zip")
    
    files_to_pack = [
        "SKILL.md",
        "mcp_shield.py",
        "mcp_server.py",
        "test_mcp_shield.py",
        "scripts/mcp_shield_runner.py",
        "smithery.yaml",
        "Dockerfile",
        "glama.json",
        "server.json",
        "clawhub.json",
        ".cursorrules",
        "mcp_shield_logo_512.png",
        "README.md"
    ]
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rel in files_to_pack:
            p = base_dir / rel
            if p.exists():
                zf.write(p, arcname=rel)
                print(f"Packed: {rel}")
            else:
                print(f"WARNING: Missing {rel}")
                
    # Copy to marketplace-tracker/submissions
    import shutil
    shutil.copy2(zip_path, tracker_zip)
    print(f"Created: {zip_path}")
    print(f"Created: {tracker_zip}")

    # Copy logo and SKILL.md to submission dir for easy web upload
    shutil.copy2(base_dir / "mcp_shield_logo_512.png", sub_dir / "mcp_shield_logo_512.png")
    shutil.copy2(base_dir / "SKILL.md", sub_dir / "SKILL.md")
    print("Copied standalone artifacts to submission dir.")

if __name__ == "__main__":
    create_bundle()
