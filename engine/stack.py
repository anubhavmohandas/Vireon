"""
scanner/stack.py — Dependency stack detection

Detects what packages a repo uses and at what versions.
Supports: requirements.txt, pyproject.toml, Pipfile, package.json, Gemfile, go.mod, Cargo.toml
No SAGE dependency — Vireon standalone.
"""

import json
import os
import re
from pathlib import Path


def detect_stack(repo_path: str) -> dict[str, str]:
    """
    Scan a repo and return all detected packages with their versions.
    Returns: {package_name_normalized: version}
    """
    path = Path(repo_path)
    packages = {}

    # Python
    for req_file in ["requirements.txt", "requirements-dev.txt",
                     "requirements-prod.txt", "requirements-test.txt",
                     "requirements-base.txt"]:
        req_path = path / req_file
        if req_path.exists():
            found = _parse_requirements_txt(req_path)
            packages.update(found)
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[stack] Found {len(found)} packages in {req_file}")

    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        found = _parse_pyproject_toml(pyproject)
        packages.update(found)
        if found:
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[stack] Found {len(found)} packages in pyproject.toml")

    pipfile = path / "Pipfile"
    if pipfile.exists():
        found = _parse_pipfile(pipfile)
        packages.update(found)
        if found:
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[stack] Found {len(found)} packages in Pipfile")

    # Node.js
    package_json = path / "package.json"
    if package_json.exists():
        found = _parse_package_json(package_json)
        packages.update(found)
        if found:
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[stack] Found {len(found)} packages in package.json")

    # Go
    go_mod = path / "go.mod"
    if go_mod.exists():
        found = _parse_go_mod(go_mod)
        packages.update(found)
        if found:
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[stack] Found {len(found)} packages in go.mod")

    # Rust
    cargo = path / "Cargo.toml"
    if cargo.exists():
        found = _parse_cargo_toml(cargo)
        packages.update(found)
        if found:
            if os.getenv("VIREON_VERBOSE") == "1":
                print(f"[stack] Found {len(found)} packages in Cargo.toml")

    if not packages and os.getenv("VIREON_VERBOSE") == "1":
        print("[stack] No dependency files found in repo.")

    return packages


def _normalize_pkg(name: str) -> str:
    return name.lower().replace("-", "_").strip()


def _parse_requirements_txt(path: Path) -> dict[str, str]:
    packages = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            line = line.split("#")[0].strip()
            if not line:
                continue
            line = re.sub(r'\[[^\]]*\]', '', line)
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=><!~].+)?$", line)
            if match:
                name = _normalize_pkg(match.group(1))
                version = match.group(2).strip() if match.group(2) else "any"
                if version.startswith("=="):
                    version = version[2:].strip()
                packages[name] = version
    return packages


def _parse_package_json(path: Path) -> dict[str, str]:
    packages = {}
    try:
        with open(path) as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies", "peerDependencies"]:
            for name, version in data.get(section, {}).items():
                clean = re.sub(r"^[\^~>=<]", "", version).strip()
                packages[_normalize_pkg(name)] = clean
    except Exception:
        pass
    return packages


def _parse_pyproject_toml(path: Path) -> dict[str, str]:
    packages = {}
    try:
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return packages
        with open(path, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=><!~].+)?$", dep.strip())
            if match:
                name = _normalize_pkg(match.group(1))
                version = match.group(2).strip() if match.group(2) else "any"
                if version.startswith("=="):
                    version = version[2:].strip()
                packages[name] = version
    except Exception:
        pass
    return packages


def _parse_pipfile(path: Path) -> dict[str, str]:
    packages = {}
    current_section = None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("[packages]"):
                    current_section = "packages"
                elif line.startswith("[dev-packages]"):
                    current_section = "dev"
                elif line.startswith("["):
                    current_section = None
                elif current_section and "=" in line:
                    parts = line.split("=", 1)
                    name = _normalize_pkg(parts[0].strip())
                    version = parts[1].strip().strip('"').strip("'")
                    if version == "*":
                        version = "any"
                    packages[name] = version
    except Exception:
        pass
    return packages


def _parse_go_mod(path: Path) -> dict[str, str]:
    packages = {}
    try:
        with open(path) as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                if in_require or line.startswith("require "):
                    line = line.replace("require ", "").strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0].split("/")[-1]
                        version = parts[1].lstrip("v")
                        packages[_normalize_pkg(name)] = version
    except Exception:
        pass
    return packages


def _parse_cargo_toml(path: Path) -> dict[str, str]:
    packages = {}
    try:
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return packages
        with open(path, "rb") as f:
            data = tomllib.load(f)
        for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    version = spec.get("version", "any")
                else:
                    version = "any"
                packages[_normalize_pkg(name)] = version
    except Exception:
        pass
    return packages
