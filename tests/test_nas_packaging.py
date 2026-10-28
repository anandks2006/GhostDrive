"""
test_nas_packaging.py -- NAS/self-hosted packaging artifacts: Docker image +
compose, Unraid template, Synology spk scaffolding.

Parse/lint only — there is no Docker daemon in CI and no NAS on the build
box, so nothing here builds an image or installs a package. These tests pin
the cross-file invariants (data-dir env var, healthcheck route, version,
loopback story) so the packaging cannot silently drift from the app.
"""

import re
import shutil
import subprocess
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ROOT / "packaging" / "docker"
UNRAID = ROOT / "packaging" / "unraid"
SYNOLOGY = ROOT / "packaging" / "synology"


class TestNasPackagingFilesExist:
    """Every artifact this packaging surface promises must be on disk."""

    @pytest.mark.parametrize(
        "rel",
        [
            "packaging/docker/Dockerfile",
            "packaging/docker/docker-compose.yml",
            "packaging/docker/.dockerignore",
            "packaging/docker/README.md",
            "packaging/unraid/ghostdrive.xml",
            "packaging/unraid/README.md",
            "packaging/synology/SPK_BUILD.md",
            "packaging/synology/package.sh",
            "packaging/synology/INFO",
            "tests/test_nas_packaging.py",
        ],
    )
    def test_file_exists(self, rel):
        assert (ROOT / rel).exists(), f"missing packaging artifact: {rel}"


class TestDockerfile:
    @pytest.fixture(scope="class")
    def text(self):
        return (DOCKER / "Dockerfile").read_text(encoding="utf-8")

    def test_base_images_are_pinned_python_312_slim(self, text):
        """Both stages must pin python:3.12-slim — no latest, no bare python:3."""
        froms = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
        assert froms, "no FROM lines in Dockerfile"
        for ref in froms:
            assert re.match(r"^python:3\.12-slim", ref), (
                f"unpinned/base-changing FROM ref: {ref} "
                "(expected python:3.12-slim-bookworm or python:3.12-slim)"
            )
            assert "latest" not in ref
        # The spec'd minor pin: at least one stage names the distro variant.
        assert any("slim-bookworm" in ref for ref in froms)

    def test_multi_stage_build(self, text):
        assert len(re.findall(r"^FROM\s+", text, re.MULTILINE)) >= 2, (
            "expected a multi-stage build (wheel builder -> slim runtime)"
        )

    def test_non_root_user(self, text):
        assert re.search(r"^USER\s+ghostdrive\s*$", text, re.MULTILINE)
        # uid 1000 as spec'd, created in the runtime stage.
        assert re.search(r"useradd\s.*--uid\s+1000", text)

    def test_volume_and_expose(self, text):
        assert re.search(r"^VOLUME\s+/data\s*$", text, re.MULTILINE)
        assert re.search(r"^EXPOSE\s+8000\s*$", text, re.MULTILINE)

    def test_healthcheck_present_and_uses_stdlib_urllib(self, text):
        # Slim images have no curl; the probe must be python stdlib urllib.
        assert "HEALTHCHECK" in text
        assert "urllib.request.urlopen" in text
        assert "curl" not in text.split("HEALTHCHECK", 1)[1]

    def test_data_dir_env_var_is_the_real_mechanism(self, text):
        # GHOSTDRIVE_DATA_DIR is what ghostdrive/utils/platform.py reads.
        assert re.search(r"^ENV\s+GHOSTDRIVE_DATA_DIR=/data\s*$", text, re.MULTILINE)

    def test_entrypoint_uses_the_cli_host_override(self, text):
        """
        server.py:main() hardcodes 127.0.0.1; `ghostdrive-cli serve --host`
        is the only override in the codebase. The image must go through it,
        and must not try to open a browser inside a container.
        """
        entry = re.search(r"^ENTRYPOINT\s+(.*)$", text, re.MULTILINE)
        assert entry, "no ENTRYPOINT"
        line = entry.group(1)
        assert "ghostdrive-cli" in line
        assert "serve" in line
        assert '"--host", "0.0.0.0"' in line
        assert '"--port", "8000"' in line
        assert "--no-browser" in line


class TestComposeYaml:
    @pytest.fixture(scope="class")
    def compose(self):
        yaml = pytest.importorskip("yaml", reason="PyYAML not available")
        return yaml.safe_load((DOCKER / "docker-compose.yml").read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def text(self):
        return (DOCKER / "docker-compose.yml").read_text(encoding="utf-8")

    def test_no_obsolete_version_key(self, compose, text):
        assert "version" not in compose, "obsolete top-level `version:` key present"
        assert not re.search(r"^version:", text, re.MULTILINE)

    def test_service_shape(self, compose):
        svc = compose["services"]["ghostdrive"]
        assert svc["build"]["dockerfile"] == "packaging/docker/Dockerfile"
        assert svc["build"]["context"] in ("../..", ".")
        assert svc["restart"] == "unless-stopped"

    def test_volume_maps_to_data_dir(self, compose):
        svc = compose["services"]["ghostdrive"]
        assert any(
            str(v).endswith(":/data") for v in svc["volumes"]
        ), "no volume mounted at /data (GHOSTDRIVE_DATA_DIR target)"

    def test_data_dir_env_var_set(self, compose):
        env = compose["services"]["ghostdrive"]["environment"]
        assert env["GHOSTDRIVE_DATA_DIR"] == "/data"

    def test_port_published_on_host_loopback(self, compose):
        """
        The default publish must be host-loopback: the app's threat model is
        loopback-only, and a plain `ports: 8000:8000` would silently make it
        a LAN service with no TLS and no auth beyond the vault lock.
        """
        svc = compose["services"]["ghostdrive"]
        published = [str(p) for p in svc["ports"]]
        assert any(p.startswith("127.0.0.1:8000:8000") for p in published), (
            f"expected an active 127.0.0.1:8000:8000 mapping, got {published}"
        )

    def test_logging_rotation(self, compose):
        opts = compose["services"]["ghostdrive"]["logging"]["options"]
        assert opts["max-size"] == "10m"
        assert str(opts["max-file"]) == "3"


class TestDockerignore:
    def test_excludes_git_and_tests(self):
        text = (DOCKER / ".dockerignore").read_text(encoding="utf-8")
        entries = {
            line.strip().rstrip("/").lstrip("!").strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        assert ".git" in entries
        assert "tests" in entries

    def test_does_not_exclude_readme_needed_by_wheel_build(self):
        """
        pyproject declares readme = "README.md"; excluding *.md at the context
        root would break the wheel build in the Dockerfile's first COPY.
        """
        text = (DOCKER / ".dockerignore").read_text(encoding="utf-8")
        assert "*.md" not in text


class TestUnraidTemplate:
    @pytest.fixture(scope="class")
    def root(self):
        return ET.parse(UNRAID / "ghostdrive.xml").getroot()

    def test_root_and_name(self, root):
        assert root.tag == "Container"
        assert root.findtext("Name") == "GhostDrive"

    def test_repository_and_network(self, root):
        repo = root.findtext("Repository")
        assert repo and "ghostdrive" in repo
        # Bridge + port mapping, matching the image's --host 0.0.0.0-in-
        # container-namespace design (see packaging/docker/README.md).
        assert root.findtext("Network") in ("bridge", "host", "none")

    def test_path_maps_appdata_to_data(self, root):
        paths = root.findall("Path")
        assert paths, "no <Path> entries"
        containers = {p.findtext("Container") for p in paths}
        assert "/data" in containers
        data_path = next(p for p in paths if p.findtext("Container") == "/data")
        host = data_path.findtext("Host") or ""
        assert "appdata" in host, f"host path {host!r} not an appdata-style location"
        assert (data_path.findtext("Mode") or "") == "rw"

    def test_port_is_numeric(self, root):
        ports = root.findall("Port")
        assert ports, "no <Port> entries"
        for port in ports:
            int(port.findtext("HostPort"))
            int(port.findtext("ContainerPort"))
            assert port.findtext("Protocol") in ("tcp", "udp", "tcp,udp")

    def test_variable_for_data_dir(self, root):
        variables = {
            v.findtext("Name"): v.findtext("Value") for v in root.findall("Variable")
        }
        assert variables.get("GHOSTDRIVE_DATA_DIR") == "/data"


class TestSynologyInfo:
    @pytest.fixture(scope="class")
    def fields(self):
        info = {}
        for line in (SYNOLOGY / "INFO").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            info[key.strip()] = value.strip().strip('"')
        return info

    def test_required_dsm7_fields(self, fields):
        for key in ("package", "version", "arch", "maintainer",
                    "displayname", "description"):
            assert fields.get(key), f"INFO missing required field: {key}"
        assert fields["package"] == "ghostdrive"
        assert fields["arch"] == "x86_64"

    def test_version_matches_package_version(self, fields):
        """INFO version = leading d.d.d of ghostdrive.__version__ (DSM's
        version field does not take PEP 440 suffixes like -alpha)."""
        init = (ROOT / "ghostdrive" / "__init__.py").read_text(encoding="utf-8")
        m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
        assert m, "could not parse ghostdrive.__version__"
        expected = m.group(1).split("-")[0]
        assert fields["version"] == expected, (
            f"INFO version {fields['version']!r} != __version__ prefix {expected!r}"
        )
        assert re.fullmatch(r"\d+\.\d+\.\d+", fields["version"])

    def test_version_also_matches_pyproject(self, fields):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        pyproject_version = data["tool"]["poetry"]["version"].split("-")[0]
        assert fields["version"] == pyproject_version


class TestPackageScript:
    def test_shebang_and_invocation_shape(self):
        text = (SYNOLOGY / "package.sh").read_text(encoding="utf-8")
        assert text.startswith("#!/bin/sh")
        # The script assembles the standard minimal spk layout.
        for token in ("package.tgz", "INFO", "start-stop-status", "ghostdrive.spk"):
            assert token in text

    def test_start_stop_handles_all_three_verbs(self):
        text = (SYNOLOGY / "package.sh").read_text(encoding="utf-8")
        for verb in ("start)", "stop)", "status)"):
            assert verb in text
        # The pidfile must live under the package's var dir, per the spec
        # (composed as /var/packages/ghostdrive/var/ via PACKAGE + VAR).
        assert 'VAR="/var/packages/${PACKAGE}/var"' in text
        assert 'PIDFILE="${VAR}/ghostdrive.pid"' in text

    def test_launch_is_nohup_with_data_dir_env(self):
        text = (SYNOLOGY / "package.sh").read_text(encoding="utf-8")
        assert "nohup" in text
        assert "GHOSTDRIVE_DATA_DIR=" in text

    def test_heredoc_markers_are_paired(self):
        """Cheap quoting sanity that works without a POSIX shell on Windows."""
        text = (SYNOLOGY / "package.sh").read_text(encoding="utf-8")
        markers = re.findall(r"<<'EOF'", text)
        closers = re.findall(r"^\s*EOF\s*$", text, re.MULTILINE)
        assert markers, "no heredocs found"
        assert len(markers) == len(closers), (
            f"{len(markers)} heredoc openers vs {len(closers)} EOF closers"
        )

    @pytest.mark.skipif(
        shutil.which("sh") is None,
        reason="no POSIX sh on this host (Windows without Git/WSL sh on PATH)",
    )
    def test_posix_syntax_check(self):
        """`sh -n` parses without executing — the only automated guarantee we
        can make without a DSM box."""
        proc = subprocess.run(
            ["sh", "-n", str(SYNOLOGY / "package.sh")],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"sh -n failed: {proc.stderr}"


class TestHealthcheckEndpointIsRealRoute:
    def test_healthcheck_path_composes_from_real_router(self):
        """
        The Dockerfile's healthcheck path must be built from an actual router
        prefix + GET route in ghostdrive/web/routes/ — catches drift if auth
        routes are renamed.
        """
        df = (DOCKER / "Dockerfile").read_text(encoding="utf-8")
        m = re.search(r"urlopen\('http://127\.0\.0\.1:\d+(/[^']*)'", df)
        assert m, "healthcheck URL not found in Dockerfile"
        healthcheck_path = m.group(1)

        auth_src = (ROOT / "ghostdrive" / "web" / "routes" / "auth.py").read_text(
            encoding="utf-8"
        )
        prefix = re.search(r'APIRouter\(prefix="([^"]+)"', auth_src)
        assert prefix, "auth router prefix not found in auth.py"
        get_routes = re.findall(r'@router\.get\("([^"]+)"', auth_src)
        composed = {prefix.group(1) + route for route in get_routes}
        assert healthcheck_path in composed, (
            f"healthcheck path {healthcheck_path} is not a GET route under "
            f"{prefix.group(1)} (available: {sorted(composed)})"
        )

    def test_healthcheck_answers_while_locked(self):
        """The route must not require an unlocked vault — it stats a file."""
        auth_src = (ROOT / "ghostdrive" / "web" / "routes" / "auth.py").read_text(
            encoding="utf-8"
        )
        status_route = auth_src.split('@router.get("/status"', 1)[1]
        body = status_route.split("@router.", 1)[0]
        # Read-only file stats, and no auth gate: the handler must answer
        # identically whether the vault is locked or not.
        assert "state.keystore_path.exists()" in body
        assert "HTTPException" not in body


class TestDockerReadmeTellsTheTruth:
    @pytest.fixture(scope="class")
    def text(self):
        return (DOCKER / "README.md").read_text(encoding="utf-8")

    def test_mentions_data_dir_env_var(self, text):
        assert "GHOSTDRIVE_DATA_DIR" in text

    def test_tells_the_loopback_story(self, text):
        """README must carry the loopback caveat and the override mechanism,
        not pretend the container magically changes the app's bind."""
        lowered = text.lower()
        assert "loopback" in lowered
        assert "127.0.0.1" in text
        assert "--host" in text  # the CLI override the ENTRYPOINT relies on

    def test_documents_what_is_not_included(self, text):
        assert "no tls" in text.lower()
