import functools
import hashlib
import http.server
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
import zipfile


REPO = Path(__file__).resolve().parents[2]


class DownloadHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        super().do_GET()

    def log_message(self, *args):
        pass


class UpdaterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures = Path(os.environ["UPDATER_FIXTURES"])
        cls.original = (fixtures / "location.mmdb").read_bytes()
        cls.replacement = (fixtures / "security.mmdb").read_bytes()
        assert cls.original != cls.replacement
        for data in [cls.original, cls.replacement]:
            assert b"\xab\xcd\xefMaxMind.com" in data[-131072:]

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="ipgeo-updater-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.downloads = self.root / "downloads"
        self.downloads.mkdir()
        self.installed = self.root / "installed"
        self.installed.mkdir()
        self.target = self.installed / "location.mmdb"
        handler = functools.partial(DownloadHandler, directory=str(self.downloads))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.requests = []
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base_url = "http://127.0.0.1:" + str(self.server.server_port)

    def archive(self, data, digest=None):
        path = self.downloads / "database.zip"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("release/location.mmdb", data)
            z.writestr("release/checksum.txt", (digest or hashlib.sha256(data).hexdigest()) + "  location.mmdb\n")
        return path

    def run_updater(self, path="database.zip", expected=0, **settings):
        env = dict(os.environ)
        for key in ["IPGEO_INTERVAL", "IPGEO_RELOAD", "IPGEO_SIGNATURE_URLS", "IPGEO_PUBLIC_KEY", "IPGEO_PUBLIC_KEY_PEM", "IPGEO_VALIDATE"]:
            env.pop(key, None)
        env.update(settings)
        env["IPGEO_URLS"] = self.base_url + "/" + path + "?apiKey=updater-test-secret"
        image = os.environ.get("UPDATER_IMAGE")
        if image:
            command = ["docker", "run", "--rm", "--network", "host", "-v", str(self.root) + ":" + str(self.root)]
            for key in ["IPGEO_URLS", *settings]:
                command.extend(["-e", key])
            command.append(image)
        else:
            command = ["sh", str(REPO / "examples/updater/ipgeolocation-update.sh")]
        result = subprocess.run(command + ["-d", str(self.installed)], env=env, capture_output=True, text=True, timeout=45)
        output = result.stdout + result.stderr
        self.assertEqual(expected, result.returncode, output)
        self.assertNotIn("updater-test-secret", output)
        self.assertFalse(list(self.installed.glob(".ipgeo-update.*")), output)
        self.assertIn("/" + path + "?apiKey=updater-test-secret", self.server.requests)
        return output

    def test_archive_install_and_unchanged_file(self):
        self.archive(self.original)
        self.run_updater()
        self.assertEqual(self.original, self.target.read_bytes())
        self.assertEqual(0o644, self.target.stat().st_mode & 0o777)
        inode = self.target.stat().st_ino
        self.assertIn("unchanged", self.run_updater())
        self.assertEqual(inode, self.target.stat().st_ino)

    def test_replacement_keeps_open_file_unchanged(self):
        self.target.write_bytes(self.original)
        self.archive(self.replacement)
        with self.target.open("rb") as previous:
            self.run_updater()
            self.assertEqual(self.original, previous.read())
        self.assertEqual(self.replacement, self.target.read_bytes())

    def test_bad_checksum_preserves_database(self):
        self.target.write_bytes(self.original)
        self.archive(self.replacement, "0" * 64)
        self.assertIn("checksum verification FAILED", self.run_updater(expected=1))
        self.assertEqual(self.original, self.target.read_bytes())

    def test_invalid_database_preserves_database(self):
        self.target.write_bytes(self.original)
        self.archive(b"not an MMDB file")
        self.assertIn("not a valid MMDB", self.run_updater(expected=1))
        self.assertEqual(self.original, self.target.read_bytes())

    def test_raw_database_download(self):
        (self.downloads / "location.mmdb").write_bytes(self.original)
        self.run_updater("location.mmdb")
        self.assertEqual(self.original, self.target.read_bytes())

    def signed_archive(self):
        archive = self.archive(self.original)
        key, public = self.root / "key.pem", self.root / "public.pem"
        signature = self.downloads / "database.sig"
        for args in [
            ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
            ["pkey", "-in", str(key), "-pubout", "-out", str(public)],
            ["dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(archive)],
        ]:
            subprocess.run(["openssl", *args], capture_output=True, check=True)
        return public, signature

    def test_signature_with_key_file_and_inline_key(self):
        public, _ = self.signed_archive()
        for setting in [{"IPGEO_PUBLIC_KEY": str(public)}, {"IPGEO_PUBLIC_KEY_PEM": public.read_text()}]:
            self.assertIn("signature verified", self.run_updater(
                IPGEO_SIGNATURE_URLS=self.base_url + "/database.sig", **setting))
            self.assertEqual(self.original, self.target.read_bytes())

    def test_bad_signature_preserves_database(self):
        public, signature = self.signed_archive()
        signature.write_bytes(b"invalid signature")
        self.target.write_bytes(self.replacement)
        self.assertIn("signature verification FAILED", self.run_updater(
            expected=1, IPGEO_PUBLIC_KEY=str(public), IPGEO_SIGNATURE_URLS=self.base_url + "/database.sig"))
        self.assertEqual(self.replacement, self.target.read_bytes())

    def test_download_failure_preserves_database(self):
        self.target.write_bytes(self.original)
        self.assertIn("download failed", self.run_updater("missing.zip", expected=1))
        self.assertEqual(self.original, self.target.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
