#!/usr/bin/env python3
"""Exercise a partial publication and a retry with immutable tags using a local Docker stand-in."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("release-oci.sh").resolve()
SOURCE = "https://github.com/example/toolkit"
REVISION = "f" * 40
REPO = "docker.io/example/toolkit"

DOCKER = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
db = Path(os.environ["OCI_FAKE_STATE"])
state = json.loads(db.read_text())
tags, images, indices = (state[k] for k in ("tags", "images", "indices"))
a = sys.argv[1:]
def resolve(ref):
    return ref.split("@")[1] if "@" in ref else tags[ref]
try:
    if a[:3] == ["buildx", "imagetools", "inspect"]:
        digest = resolve(a[3])
        print(json.dumps(indices[digest] if "--raw" in a else {"digest": digest}))
    elif a[:3] == ["buildx", "imagetools", "create"]:
        assert a[4] not in tags, "immutable image tag"
        sources = [resolve(ref) for ref in a[5:]]
        digest = sources[0]
        if len(sources) == 2:
            digest = "sha256:" + "c" * 64
            indices[digest] = {"manifests": [
                {"platform": {"os": "linux", "architecture": arch}, "digest": image}
                for arch, image in zip(("amd64", "arm64"), sources, strict=True)
            ]}
        tags[a[4]] = digest
    elif a[:2] == ["image", "inspect"]:
        digest = resolve(a[2])
        print(digest if a[-1] == "{{.Id}}" else json.dumps(images[digest]))
    elif a[0] == "tag":
        tags[a[2]] = resolve(a[1])
    elif a[0] != "pull":
        raise AssertionError(a)
except KeyError:
    sys.exit(1)
db.write_text(json.dumps(state))
"""


class Publication(unittest.TestCase):
    def test_retries_retest_the_staged_digest_and_promote_immutably(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(DOCKER, encoding="utf-8")
            docker.chmod(0o700)
            state = root / "state.json"
            arm, amd, rebuilt = ("sha256:" + value * 64 for value in "abd")
            tags = {f"{REPO}:v1.0.0-amd64-run-42": amd,
                    f"{REPO}:v1.0.0-arm64-run-42": arm, "tested": rebuilt}
            labels = {"org.opencontainers.image.revision": REVISION, "org.opencontainers.image.source": SOURCE}
            state.write_text(json.dumps({"tags": tags, "images": dict.fromkeys((amd, arm, rebuilt), labels),
                                         "indices": {}}), encoding="utf-8")
            env = dict(os.environ, PATH=f"{root}{os.pathsep}{os.environ['PATH']}", OCI_FAKE_STATE=str(state))

            def run(*args, check=True):
                return subprocess.run(["bash", str(SCRIPT), *args], env=env, check=check,
                                      text=True, capture_output=True)

            staged = f"{REPO}:v1.0.0-amd64-run-42"
            self.assertNotEqual(run("stage", "tested", staged, REVISION, SOURCE, check=False).returncode, 0)
            self.assertNotEqual(run("restore", "tested", staged, "e" * 40, SOURCE, check=False).returncode, 0)
            run("restore", "tested", staged, REVISION, SOURCE)
            run("stage", "tested", staged, REVISION, SOURCE)
            published = run("promote", REPO, "v1.0.0", "42").stdout.strip()
            self.assertEqual(published, "sha256:" + "c" * 64)
            self.assertEqual(run("promote", REPO, "v1.0.0", "42").stdout.strip(), published)

            modified = json.loads(state.read_text(encoding="utf-8"))
            modified["tags"][f"{REPO}:v1.0.0"] = rebuilt
            state.write_text(json.dumps(modified), encoding="utf-8")
            self.assertNotEqual(run("promote", REPO, "v1.0.0", "42", check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
