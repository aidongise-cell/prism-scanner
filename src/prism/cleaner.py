"""Safe cleanup engine with backup and rollback support."""
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from .models import Finding


BACKUP_DIR = Path.home() / ".prism" / "backups"


class CleanupPlan:
    """A plan of cleanup actions to be taken."""

    def __init__(self):
        self.actions: list[dict] = []

    def add_remove_file(self, path: str, finding: Finding):
        self.actions.append({
            "type": "remove_file",
            "path": path,
            "rule_id": finding.rule_id,
            "title": finding.title,
        })

    def add_remove_line(self, path: str, line_num: int, line_content: str, finding: Finding):
        self.actions.append({
            "type": "remove_line",
            "path": path,
            "line": line_num,
            "content": line_content,
            "rule_id": finding.rule_id,
            "title": finding.title,
        })

    def add_fix_permissions(self, path: str, current_mode: str, target_mode: str, finding: Finding):
        self.actions.append({
            "type": "fix_permissions",
            "path": path,
            "current_mode": current_mode,
            "target_mode": target_mode,
            "rule_id": finding.rule_id,
            "title": finding.title,
        })

    def add_remove_crontab_entry(self, entry: str, finding: Finding):
        self.actions.append({
            "type": "remove_crontab",
            "entry": entry,
            "rule_id": finding.rule_id,
            "title": finding.title,
        })


def generate_plan(findings: list[Finding]) -> CleanupPlan:
    """Generate a cleanup plan from residue findings."""
    plan = CleanupPlan()

    for f in findings:
        if f.rule_id in ("R2", "R3", "R4") and f.file_path:
            # LaunchAgents, systemd, sudoers — remove file
            plan.add_remove_file(f.file_path, f)

        elif f.rule_id == "R5" and f.file_path and f.line:
            # Shell config — remove specific line
            plan.add_remove_line(f.file_path, f.line, f.code_snippet or "", f)

        elif f.rule_id == "R7" and f.file_path:
            # Cache directories — remove
            plan.add_remove_file(f.file_path, f)

        elif f.rule_id == "R8" and f.file_path:
            # Credentials — fix permissions
            plan.add_fix_permissions(f.file_path, "", "600", f)

        elif f.rule_id == "R1" and f.code_snippet:
            # Crontab — remove entry
            plan.add_remove_crontab_entry(f.code_snippet, f)

        elif f.rule_id == "R6" and f.file_path:
            # Git hooks — remove file
            plan.add_remove_file(f.file_path, f)

        elif f.rule_id in ("R9", "R10"):
            # Network config / global packages — just report, don't auto-fix
            pass

    return plan


def print_plan(plan: CleanupPlan):
    """Print the cleanup plan in a readable format."""
    if not plan.actions:
        print("  No actionable cleanup items found.")
        return

    print(f"  Cleanup Plan: {len(plan.actions)} actions\n")
    for i, action in enumerate(plan.actions, 1):
        atype = action["type"]
        print(f"  [{i}] {action['title']} ({action['rule_id']})")

        if atype == "remove_file":
            print(f"      Action: DELETE {action['path']}")
        elif atype == "remove_line":
            print(f"      Action: REMOVE line {action['line']} from {action['path']}")
            print(f"      Content: {action['content'][:80]}")
        elif atype == "fix_permissions":
            print(f"      Action: chmod {action['target_mode']} {action['path']}")
        elif atype == "remove_crontab":
            print(f"      Action: Remove crontab entry: {action['entry'][:80]}")
        print()


def execute_plan(plan: CleanupPlan, interactive: bool = True) -> str:
    """Execute the cleanup plan with backups. Returns backup ID."""
    if not plan.actions:
        return ""

    # Create backup directory
    backup_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / backup_id
    backup_path.mkdir(parents=True, exist_ok=True)

    manifest = {"id": backup_id, "created": str(datetime.now()), "items": []}
    executed = 0

    for action in plan.actions:
        if interactive:
            response = input(f"  Execute: {action['title']}? [y/N/q] ").strip().lower()
            if response == "q":
                break
            if response != "y":
                continue

        try:
            _execute_action(action, backup_path, manifest)
            executed += 1
        except Exception as e:
            print(f"  Error: {e}")

    # Save manifest
    manifest["executed"] = executed
    (backup_path / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"\n  Executed {executed}/{len(plan.actions)} actions")
    print(f"  Backup saved to: {backup_path}")
    print(f"  Rollback with: prism clean --rollback {backup_id}")

    return backup_id


def _execute_action(action: dict, backup_path: Path, manifest: dict):
    """Execute a single cleanup action with backup."""
    atype = action["type"]

    if atype == "remove_file":
        path = Path(action["path"])
        if path.exists():
            # Backup
            backup_file = backup_path / path.name
            if path.is_dir():
                shutil.copytree(path, backup_file)
                shutil.rmtree(path)
            else:
                shutil.copy2(path, backup_file)
                path.unlink()
            manifest["items"].append({"action": "removed", "original": str(path), "backup": str(backup_file)})

    elif atype == "remove_line":
        path = Path(action["path"])
        if path.exists():
            # Backup entire file
            backup_file = backup_path / f"{path.name}.{action['line']}.bak"
            shutil.copy2(path, backup_file)
            # Remove the line
            lines = path.read_text().splitlines(keepends=True)
            line_idx = action["line"] - 1
            if 0 <= line_idx < len(lines):
                lines.pop(line_idx)
                path.write_text("".join(lines))
            manifest["items"].append({"action": "removed_line", "file": str(path), "line": action["line"], "backup": str(backup_file)})

    elif atype == "fix_permissions":
        path = Path(action["path"])
        if path.exists():
            old_mode = oct(path.stat().st_mode)[-3:]
            manifest["items"].append({"action": "chmod", "file": str(path), "old_mode": old_mode, "new_mode": action["target_mode"]})
            os.chmod(path, int(action["target_mode"], 8))

    elif atype == "remove_crontab":
        import subprocess
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0:
            old_crontab = result.stdout
            (backup_path / "crontab.bak").write_text(old_crontab)
            new_lines = [l for l in old_crontab.splitlines(keepends=True) if action["entry"][:60] not in l]
            new_crontab = "".join(new_lines)
            subprocess.run(["crontab", "-"], input=new_crontab, text=True)
            manifest["items"].append({"action": "removed_crontab", "backup": str(backup_path / "crontab.bak")})


def rollback(backup_id: str):
    """Rollback a previous cleanup using backup ID."""
    backup_path = BACKUP_DIR / backup_id
    if not backup_path.exists():
        print(f"  Backup not found: {backup_id}")
        print(f"  Available backups:")
        if BACKUP_DIR.exists():
            for d in sorted(BACKUP_DIR.iterdir()):
                if d.is_dir():
                    print(f"    {d.name}")
        return

    manifest_file = backup_path / "manifest.json"
    if not manifest_file.exists():
        print(f"  Invalid backup: no manifest.json")
        return

    manifest = json.loads(manifest_file.read_text())
    print(f"  Rolling back backup {backup_id} ({len(manifest.get('items', []))} items)")

    for item in manifest.get("items", []):
        try:
            if item["action"] == "removed":
                backup_file = Path(item["backup"])
                original = Path(item["original"])
                if backup_file.exists():
                    if backup_file.is_dir():
                        shutil.copytree(backup_file, original)
                    else:
                        shutil.copy2(backup_file, original)
                    print(f"  Restored: {original}")

            elif item["action"] == "removed_line":
                backup_file = Path(item["backup"])
                original = Path(item["file"])
                if backup_file.exists():
                    shutil.copy2(backup_file, original)
                    print(f"  Restored: {original}")

            elif item["action"] == "chmod":
                path = Path(item["file"])
                if path.exists():
                    os.chmod(path, int(item["old_mode"], 8))
                    print(f"  Restored permissions: {path}")

            elif item["action"] == "removed_crontab":
                import subprocess
                backup_file = Path(item["backup"])
                if backup_file.exists():
                    subprocess.run(["crontab", "-"], input=backup_file.read_text(), text=True)
                    print(f"  Restored crontab")

        except Exception as e:
            print(f"  Error restoring {item}: {e}")

    print(f"\n  Rollback complete.")
