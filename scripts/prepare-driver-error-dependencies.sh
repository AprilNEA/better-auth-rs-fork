#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
dependency_output="${1:?Specify the dependency artifact directory}"
mkdir -p "$dependency_output/graphs"
printf '%s\n' "${GITHUB_SHA:?Run from the checked-out GitHub Actions revision}" > "$dependency_output/source-sha.txt"

python3 - "$dependency_output/features-before.json" <<'PY'
import json
import sys
import tomllib
from pathlib import Path

manifest = tomllib.loads(Path("crates/seaorm/Cargo.toml").read_text())
dependencies = manifest["dependencies"]
Path(sys.argv[1]).write_text(json.dumps({
    name: {
        "features": sorted(dependencies[name].get("features", [])),
        "default-features": dependencies[name].get("default-features", True),
    }
    for name in ("sea-orm", "sea-orm-migration")
}, indent=2) + "\n")
PY

cargo add --manifest-path crates/seaorm/Cargo.toml \
  'sea-orm@=2.0.0-rc.37' 'sea-orm-migration@=2.0.0-rc.37'

python3 - "$dependency_output/features-before.json" <<'PY'
import json
import os
import re
import sys
import tomllib
from pathlib import Path

root = Path.cwd().resolve()
vendor = root / "vendor/sqlx-postgres"
package = tomllib.loads((vendor / "Cargo.toml").read_text())["package"]
assert (package["name"], package["version"]) == ("sqlx-postgres", "0.8.6")
assert (vendor / "LICENSE-MIT").is_file()
assert (vendor / "LICENSE-APACHE").is_file()
before = json.loads(Path(sys.argv[1]).read_text())
dependencies = tomllib.loads(Path("crates/seaorm/Cargo.toml").read_text())["dependencies"]
for name, original in before.items():
    current = dependencies[name]
    assert current["version"] == "=2.0.0-rc.37", (name, current)
    assert sorted(current.get("features", [])) == original["features"], name
    assert current.get("default-features", True) == original["default-features"], name

root_manifest = Path("Cargo.toml")
text = root_manifest.read_text()
workspace = tomllib.loads(text)["workspace"]
excluded = workspace.get("exclude", [])
if "vendor/sqlx-postgres" not in excluded:
    excluded.append("vendor/sqlx-postgres")
    start = text.index("[workspace]") + len("[workspace]")
    next_table = re.search(r"(?m)^\[", text[start:])
    end = start + next_table.start() if next_table else len(text)
    block = text[start:end]
    replacement = "exclude = " + json.dumps(excluded)
    if "exclude" in workspace:
        block, count = re.subn(r"(?m)^exclude\s*=\s*\[[^\]]*\]", replacement, block, count=1)
        assert count == 1, "Cannot locate the workspace exclude array"
    else:
        block = "\n" + replacement + block
    root_manifest.write_text(text[:start] + block + text[end:])

for relative in (
    "Cargo.toml",
    "compat-tests/rust-server/Cargo.toml",
    "compat-tests/schema-consumer/Cargo.toml",
    "examples/fullstack/backend/Cargo.toml",
):
    manifest = Path(relative)
    text = manifest.read_text()
    data = tomllib.loads(text)
    patch = data.get("patch", {}).get("crates-io", {})
    relative_vendor = os.path.relpath(vendor, manifest.resolve().parent)
    if "sqlx-postgres" in patch:
        assert patch["sqlx-postgres"] == {"path": relative_vendor}, relative
        continue
    entry = 'sqlx-postgres = { path = ' + json.dumps(relative_vendor) + ' }\n'
    if "crates-io" in data.get("patch", {}):
        match = re.search(r"(?m)^\[patch\.crates-io\][ \t]*$", text)
        assert match, f"Cannot locate the crates.io patch table in {relative}"
        text = text[:match.end()] + "\n" + entry + text[match.end():]
    else:
        text = text.rstrip() + "\n\n[patch.crates-io]\n" + entry
    manifest.write_text(text)
PY

dependency_manifests=(
  Cargo.toml
  compat-tests/rust-server/Cargo.toml
  compat-tests/schema-consumer/Cargo.toml
  examples/fullstack/backend/Cargo.toml
)
for dependency_index in "${!dependency_manifests[@]}"; do
  dependency_manifest="${dependency_manifests[$dependency_index]}"
  # SeaORM rc.37 pins SeaQuery rc.31 and sea-query-sqlx rc.14 exactly.
  cargo update --manifest-path "$dependency_manifest" -p sea-orm --precise 2.0.0-rc.37
  cargo update --manifest-path "$dependency_manifest" -p sqlx --precise 0.8.6
  cargo metadata --manifest-path "$dependency_manifest" --locked --all-features --format-version 1 \
    > "$dependency_output/graphs/$dependency_index.json"
done

python3 - "$dependency_output" <<'PY'
import json
import shutil
import sys
from pathlib import Path

root = Path.cwd().resolve()
output = Path(sys.argv[1])
expected = {
    "sea-orm": "2.0.0-rc.37",
    "sea-orm-migration": "2.0.0-rc.37",
    "sea-query": "1.0.0-rc.31",
    "sea-query-sqlx": "0.8.0-rc.14",
    "sqlx": "0.8.6",
    "sqlx-core": "0.8.6",
    "sqlx-postgres": "0.8.6",
}
manifests = [
    "Cargo.toml",
    "compat-tests/rust-server/Cargo.toml",
    "compat-tests/schema-consumer/Cargo.toml",
    "examples/fullstack/backend/Cargo.toml",
]
registry = "registry+https://github.com/rust-lang/crates.io-index"
summary = []
files = ["crates/seaorm/Cargo.toml"]
for index, relative in enumerate(manifests):
    graph = json.loads((output / f"graphs/{index}.json").read_text())
    selected = {}
    for name, version in expected.items():
        packages = [package for package in graph["packages"] if package["name"] == name]
        assert len(packages) == 1, (relative, name, packages)
        package = packages[0]
        assert package["version"] == version, (relative, name, package["version"])
        if name == "sqlx-postgres":
            assert package["source"] is None, (relative, package)
            assert Path(package["manifest_path"]).resolve() == root / "vendor/sqlx-postgres/Cargo.toml"
            assert package["id"] not in graph["workspace_members"], "Vendor package must not join workspace-wide checks"
        else:
            assert package["source"] == registry, (relative, package)
        selected[name] = {"version": package["version"], "source": package["source"]}
    for package in graph["packages"]:
        if package["name"].startswith("sqlx-"):
            assert package["version"] == "0.8.6", (relative, package)
    summary.append({"manifest": relative, "packages": selected})
    files.extend([relative, str(Path(relative).with_name("Cargo.lock"))])

for relative in files:
    destination = output / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / relative, destination)
(output / "validation.json").write_text(json.dumps(summary, indent=2) + "\n")
(output / "manifest.txt").write_text("\n".join(files) + "\n")
PY
