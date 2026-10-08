#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""Tests for `wire-maven.py`. Run with `scripts/test_wire_maven.py` (needs uv)."""

import importlib.util
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import pytest

_spec = importlib.util.spec_from_file_location(
    "wire_maven", Path(__file__).with_name("wire-maven.py")
)
assert _spec is not None and _spec.loader is not None
wm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wm)

VERSION = "10.4.0"
NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
AGGREGATING_MODULE = json.dumps(
    {"variants": [{"name": "jvm", "available-at": {"url": "../x"}}]}
)
JVM_METADATA = "com/wire/core-crypto-jvm/maven-metadata.xml"
JVM_JAR = f"com/wire/core-crypto-jvm/{VERSION}/core-crypto-jvm-{VERSION}.jar"


def staged_files(
    artifact_id: str, version: str = VERSION, module: str = "{}"
) -> dict[str, str]:
    """What Gradle stages for one artifact: payload, signatures, checksums and metadata."""
    files = {}
    for name, content in [
        (f"{artifact_id}-{version}.jar", "jar"),
        (f"{artifact_id}-{version}.module", module),
        (f"{artifact_id}-{version}.pom", "pom"),
    ]:
        path = f"com/wire/{artifact_id}/{version}/{name}"
        files[path] = content
        files[f"{path}.asc"] = f"signature of {name}"
        files[f"{path}.sha1"] = f"checksum of {name}"
    files[f"com/wire/{artifact_id}/maven-metadata.xml"] = "gradle's metadata"
    files[f"com/wire/{artifact_id}/maven-metadata.xml.sha1"] = (
        "gradle's metadata checksum"
    )
    return files


def metadata(*versions: str, artifact_id: str = "core-crypto-jvm") -> bytes:
    listed = "".join(f"<version>{v}</version>" for v in versions)
    return (
        f"<metadata><groupId>com.wire</groupId><artifactId>{artifact_id}</artifactId>"
        f"<versioning><versions>{listed}</versions></versioning></metadata>"
    ).encode()


def parse(xml: bytes) -> dict:
    root = ET.fromstring(xml)
    return {
        "latest": root.findtext("versioning/latest"),
        "release": root.findtext("versioning/release"),
        "versions": [e.text for e in root.findall("versioning/versions/version")],
        "lastUpdated": root.findtext("versioning/lastUpdated"),
    }


class FakeBucket:
    """S3 with conditional writes. An object's ETag is the number of the write that made it."""

    def __init__(self, objects: dict[str, bytes] | None = None):
        self.objects: dict[str, bytes] = {}
        self.etags: dict[str, str] = {}
        self.writes: list[tuple[str, str | None]] = []
        for key, body in (objects or {}).items():
            self._store(key, body)

    def _store(self, key: str, body: bytes) -> None:
        self.objects[key] = body
        self.etags[key] = f'"{len(self.writes) + 1}"'

    def put(self, key, body, *, if_none_match=False, if_match=None, cache_control=None):
        exists = key in self.objects
        if if_none_match and exists:
            return False
        if if_match is not None and (not exists or self.etags[key] != if_match):
            return False
        assert not exists or if_match is not None, f"unconditional overwrite of {key}"
        self.writes.append((key, cache_control))
        self._store(key, Path(body).read_bytes())
        return True


class FakeCdn:
    """Serves the bucket, except that `stale` responses, queued per key, come first."""

    def __init__(self, bucket: FakeBucket):
        self.bucket = bucket
        self.stale: dict[str, list] = {}

    def get(self, key):
        if self.stale.get(key):
            return self.stale[key].pop(0)
        if key not in self.bucket.objects:
            return None
        return wm.Published(self.bucket.objects[key], self.bucket.etags[key])


@pytest.fixture
def stage(tmp_path):
    """Write files into a staged repository; returns a loader for it."""

    def stage(files: dict[str, str]) -> Path:
        for path, content in files.items():
            (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / path).write_text(content)
        return tmp_path

    return stage


def load(root: Path, version: str = VERSION):
    return wm.load_repo(root, "com.wire", version, "com/wire/core-crypto")


def release(
    root: Path, bucket: FakeBucket, cdn: FakeCdn | None = None, version: str = VERSION
):
    """Release `root`; returns the pauses it took."""
    sleeps: list[float] = []
    clock = iter(range(10_000))
    wm.Release(
        load(root, version),
        bucket,
        cdn or FakeCdn(bucket),
        sleep=sleeps.append,
        clock=lambda: float(next(clock)),
        now=lambda: NOW,
    ).run()
    return sleeps


# versions


def test_versions_order_numerically_with_prereleases_first():
    versions = [
        "10.0.1",
        "10.0.0",
        "9.12.0",
        "10.0.0-rc.10",
        "10.0.0-rc.2",
        "10.0.0-pre.1",
        "9.2.0",
    ]
    assert sorted(versions, key=wm.version_key) == [
        "9.2.0",
        "9.12.0",
        "10.0.0-pre.1",
        "10.0.0-rc.2",
        "10.0.0-rc.10",
        "10.0.0",
        "10.0.1",
    ]


def test_prerelease_has_a_suffix():
    assert wm.is_prerelease("10.3.1-test1")
    assert not wm.is_prerelease("10.3.1")


# merge_metadata


def merge(existing, version=VERSION):
    return wm.merge_metadata(existing, "com.wire", "core-crypto-jvm", version, NOW)


def test_merge_creates_metadata():
    assert parse(merge(None)) == {
        "latest": VERSION,
        "release": VERSION,
        "versions": [VERSION],
        "lastUpdated": "20261007120000",
    }


def test_merge_adds_version_in_order():
    merged = parse(merge(metadata("10.3.0", "10.5.0"), version="10.4.0"))
    assert merged["versions"] == ["10.3.0", "10.4.0", "10.5.0"]
    assert (merged["latest"], merged["release"]) == ("10.5.0", "10.5.0")


def test_merge_of_listed_version_needs_no_update():
    assert merge(metadata("10.3.0", VERSION)) is None


def test_merge_never_makes_a_listed_prerelease_latest():
    merged = parse(merge(metadata("10.3.0", "11.0.0-rc.1"), version="10.4.0"))
    assert merged["versions"] == ["10.3.0", "10.4.0", "11.0.0-rc.1"]
    assert (merged["latest"], merged["release"]) == ("10.4.0", "10.4.0")


def test_merge_reads_namespaced_metadata():
    namespaced = metadata("10.3.0").replace(
        b"<metadata>", b'<metadata xmlns="http://maven.apache.org/METADATA/1.1.0">'
    )
    assert parse(merge(namespaced))["versions"] == ["10.3.0", VERSION]


def test_merge_rejects_metadata_of_another_artifact():
    with pytest.raises(wm.ReleaseError):
        merge(metadata("10.3.0", artifact_id="core-crypto-android"))


# load_repo


def test_load_ignores_gradles_metadata(stage):
    repo = load(stage(staged_files("core-crypto-jvm")))
    assert list(repo.artifacts) == ["core-crypto-jvm"]
    assert not any(path.name.startswith("maven-metadata") for path in repo.files())


def test_load_rejects_path_outside_allowed_prefix(stage):
    with pytest.raises(wm.ReleaseError, match="outside com/wire/core-crypto"):
        load(stage(staged_files("cells-sdk-kmp")))


def test_load_rejects_other_version(stage):
    with pytest.raises(wm.ReleaseError, match="not 10.4.0"):
        load(stage(staged_files("core-crypto-jvm", version="10.3.0")))


def test_load_rejects_unexpected_layout(stage):
    with pytest.raises(wm.ReleaseError, match="layout"):
        load(stage({"com/wire/core-crypto-jvm/stray.txt/deeper/file": "?"}))


def test_load_rejects_empty_repo(tmp_path):
    with pytest.raises(wm.ReleaseError, match="no artifacts"):
        load(tmp_path)


# signatures


def test_finds_unsigned_files(stage):
    files = staged_files("core-crypto-jvm")
    pom = f"com/wire/core-crypto-jvm/{VERSION}/core-crypto-jvm-{VERSION}.pom"
    del files[f"{pom}.asc"]
    assert wm.unsigned_files(load(stage(files))) == [PurePosixPath(pom)]


def test_signed_by_signing_key_or_its_primary():
    status = (
        "[GNUPG:] NEWSIG\n"
        "[GNUPG:] VALIDSIG AAAA1111BBBB2222 2026-10-07 1791374400 0 4 0 1 10 00 CCCC3333DDDD4444\n"
    )
    assert wm.signed_by(status, "bbbb2222")
    assert wm.signed_by(status, "0xDDDD4444")
    assert not wm.signed_by(status, "EEEE5555")
    assert not wm.signed_by("[GNUPG:] BADSIG BBBB2222 someone\n", "BBBB2222")


# upload order


def test_descriptors_go_last_and_aggregating_module_after_the_rest(stage):
    stage(staged_files("core-crypto-kmp", module=AGGREGATING_MODULE))
    order = [
        path.name
        for path in wm.upload_order(load(stage(staged_files("core-crypto-kmp-jvm"))))
    ]
    descriptors = [name for name in order if name.endswith((".module", ".pom"))]
    assert order[-len(descriptors) :] == descriptors
    assert descriptors == [
        f"core-crypto-kmp-jvm-{VERSION}.module",
        f"core-crypto-kmp-jvm-{VERSION}.pom",
        f"core-crypto-kmp-{VERSION}.module",
        f"core-crypto-kmp-{VERSION}.pom",
    ]


# release


def test_release_uploads_everything_then_lists_the_version(stage):
    bucket = FakeBucket()
    release(stage(staged_files("core-crypto-jvm")), bucket)

    keys = [key for key, _ in bucket.writes]
    assert len(keys) == 9 + 1
    assert bucket.writes[-1] == (JVM_METADATA, "no-cache")
    assert parse(bucket.objects[JVM_METADATA])["versions"] == [VERSION]
    assert f"{JVM_METADATA}.sha1" not in bucket.objects


def test_retry_skips_identical_objects(stage):
    files = staged_files("core-crypto-jvm")
    bucket = FakeBucket({JVM_JAR: files[JVM_JAR].encode()})
    release(stage(files), bucket)
    assert (
        f"com/wire/core-crypto-jvm/{VERSION}/core-crypto-jvm-{VERSION}.pom"
        in bucket.objects
    )


def test_refuses_to_publish_over_different_content(stage):
    bucket = FakeBucket({JVM_JAR: b"something else"})
    with pytest.raises(wm.ReleaseError, match="different content"):
        release(stage(staged_files("core-crypto-jvm")), bucket)
    assert not any(
        key.endswith((".pom", ".module", wm.METADATA)) for key in bucket.objects
    )


def test_waits_for_the_cdn_to_stop_serving_a_cached_404(stage):
    files = staged_files("core-crypto-jvm")
    bucket = FakeBucket({JVM_JAR: files[JVM_JAR].encode()})
    cdn = FakeCdn(bucket)
    cdn.stale[JVM_JAR] = [None, None]
    assert release(stage(files), bucket, cdn) == [2.0, 4.0]


def test_gives_up_when_the_cdn_never_catches_up(stage):
    files = staged_files("core-crypto-jvm")
    bucket = FakeBucket({JVM_JAR: files[JVM_JAR].encode()})
    cdn = FakeCdn(bucket)
    cdn.stale[JVM_JAR] = [None] * 1000
    with pytest.raises(wm.ReleaseError, match="never served"):
        release(stage(files), bucket, cdn)


def test_remerges_after_reading_stale_metadata(stage):
    bucket = FakeBucket({JVM_METADATA: metadata("10.3.0", "10.3.1")})
    cdn = FakeCdn(bucket)
    cdn.stale[JVM_METADATA] = [wm.Published(metadata("10.3.0"), '"stale"')]
    release(stage(staged_files("core-crypto-jvm")), bucket, cdn)
    assert parse(bucket.objects[JVM_METADATA])["versions"] == [
        "10.3.0",
        "10.3.1",
        VERSION,
    ]


def test_creates_metadata_despite_a_cached_404(stage):
    bucket = FakeBucket({JVM_METADATA: metadata("10.3.0")})
    cdn = FakeCdn(bucket)
    cdn.stale[JVM_METADATA] = [None]
    release(stage(staged_files("core-crypto-jvm")), bucket, cdn)
    assert parse(bucket.objects[JVM_METADATA])["versions"] == ["10.3.0", VERSION]


def test_prerelease_is_uploaded_but_not_listed(stage):
    bucket = FakeBucket({JVM_METADATA: metadata("10.3.0")})
    release(
        stage(staged_files("core-crypto-jvm", version="10.4.0-test1")),
        bucket,
        version="10.4.0-test1",
    )
    assert (
        "com/wire/core-crypto-jvm/10.4.0-test1/core-crypto-jvm-10.4.0-test1.pom"
        in bucket.objects
    )
    assert parse(bucket.objects[JVM_METADATA])["versions"] == ["10.3.0"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, *sys.argv[1:]]))
