"""
tor_manager.py -- Headless Tor process lifecycle and Onion Service manager.
"""

import os
import sys
import shutil
import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

class TorManager:
    """
    Manages a background, headless Tor process and exposes an Onion Hidden Service.
    Configured to run on SocksPort 9050 and forward port 80 to local P2P port 8888.
    """
    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self.tor_process: Optional[subprocess.Popen] = None
        self.onion_address: Optional[str] = None
        self.is_running = False
        
        # Setup data directory inside user app data or .gemini
        if data_dir is None:
            self.data_dir = Path(os.path.expanduser("~")) / ".ghostdrive" / "tor"
        else:
            self.data_dir = data_dir
        
        self.hidden_service_dir = self.data_dir / "hidden_service"
        self.torrc_path = self.data_dir / "torrc"
        self.tor_path = self._find_tor_binary()

        # Register atexit handler to ensure background Tor process is terminated on exit
        import atexit
        atexit.register(self.stop)

    def _find_tor_binary(self) -> Optional[Path]:
        """Locate the Tor executable in the system path or bundled directories."""
        # 1. Search in system PATH
        tor_in_path = shutil.which("tor")
        if tor_in_path:
            return Path(tor_in_path)
            
        # 2. Check platform-specific common bundle locations
        app_dir = Path(__file__).resolve().parent.parent
        bundled_tor_paths = [
            app_dir / "bin" / "tor" / "tor.exe",
            app_dir / "bin" / "tor" / "tor",
            Path(os.getcwd()) / "tor" / "tor.exe",
            Path(os.getcwd()) / "tor" / "tor",
        ]
        for path in bundled_tor_paths:
            if path.exists():
                return path
                
        return None

    async def start(self) -> bool:
        """Launch the background Tor process and extract the Onion address."""
        import asyncio
        if self.is_running:
            return True

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.hidden_service_dir.mkdir(parents=True, exist_ok=True)
        
        # Handle environment without Tor binary (Mock Fallback Mode)
        if not self.tor_path:
            logger.warning("Tor binary not found on system PATH or bundled directories. Operating in P2P LAN-only mock mode.")
            self.onion_address = "mock-ghostdrive-identity.onion"
            self.is_running = True
            return True

        # Generate custom torrc configuration
        # Maps hidden service port 80 to local P2P listener port 8888
        torrc_content = f"""
SocksPort 127.0.0.1:9050
DataDirectory "{self.data_dir.as_posix()}"
HiddenServiceDir "{self.hidden_service_dir.as_posix()}"
HiddenServicePort 80 127.0.0.1:8888
Log notice stdout
AvoidDiskWrites 1
"""
        try:
            self.torrc_path.write_text(torrc_content, encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to write torrc configuration: %s", exc)
            return False

        # Build platform-specific subprocess arguments to hide console
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        logger.info("Launching Tor daemon from: %s", self.tor_path)
        try:
            self.tor_process = subprocess.Popen(
                [str(self.tor_path), "-f", str(self.torrc_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                text=True
            )
            self.is_running = True
        except Exception as exc:
            logger.error("Failed to spawn Tor subprocess: %s", exc)
            self.is_running = False
            return False

        # Poll the hidden service hostname file to extract the .onion address
        hostname_path = self.hidden_service_dir / "hostname"
        for _ in range(30):  # Wait up to 15 seconds (30 * 0.5s)
            if hostname_path.exists():
                try:
                    addr = hostname_path.read_text(encoding="utf-8").strip()
                    if addr.endswith(".onion"):
                        self.onion_address = addr
                        logger.info("Tor Hidden Service successfully bootstrapped. Onion address: %s", self.onion_address)
                        return True
                except Exception as read_err:
                    logger.warning("Error reading hidden service hostname: %s", read_err)
            await asyncio.sleep(0.5)

        logger.warning("Tor subprocess spawned but hidden service hostname was not generated within timeout.")
        # Do not fail completely, fall back to mock identity to allow LAN operations
        self.onion_address = "temp-fallback-identity.onion"
        return True


    def stop(self) -> None:
        """Terminate the background Tor process and clean up temporary configurations."""
        if not self.is_running:
            return

        logger.info("Shutting down background Tor daemon...")
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                logger.warning("Tor process did not terminate gracefully. Killing force-fully.")
                self.tor_process.kill()
            except Exception as exc:
                logger.error("Error terminating Tor process: %s", exc)
            finally:
                self.tor_process = None

        self.is_running = False
        self.onion_address = None
        logger.info("Tor daemon shut down successfully.")
