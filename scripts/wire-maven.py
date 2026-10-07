#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Check a staged Maven repository, and release it to maven.wire.com.

Usage:
    scripts/wire-maven.py verify REPO --version VERSION [--key-id KEY_ID]
                                      [--expect-artifact ARTIFACT_ID ...]
    scripts/wire-maven.py release REPO --version VERSION [--bucket BUCKET]
                                       [--key-prefix PREFIX] [--public-url URL] [--dry-run]

REPO is a local Maven repository as Gradle's `publishAllPublicationsToWireMavenRepository`
writes it: `com/wire/<artifact>/<version>/<files>`. Gradle also writes
`com/wire/<artifact>/maven-metadata.xml`, listing only the version it just built; both
commands ignore that file, and `release` updates the published copy instead.

`verify` runs when staging. It checks the repository layout, that every file carries a
detached signature, and, given --key-id, that each signature is valid and was made by
that key. GnuPG must already know the key; `verify` does not import it.

`release` uploads a staged repository to S3. The bucket never overwrites or deletes an
object, so every upload is a conditional write. That makes a retry of a partly finished
release safe: an object that already exists with identical content counts as uploaded,
and one with different content is a hard error. A release uploads, in order:

1. every file except the `.module`/`.pom` descriptors;
2. the descriptors, those of aggregating modules (the KMP root) last. A build resolves a
   version through its descriptor, so until the descriptor exists, a partly uploaded
   version looks unpublished rather than broken;
3. each artifact's `maven-metadata.xml`, now listing the new version.

A pre-release version (one with a `-suffix`) is uploaded but never listed in
`maven-metadata.xml`, so only a build that asks for that exact version can find it. Tools
disagree on how to order such suffixes (Maven sorts `10.3.1-test1` after `10.3.1`, Gradle
before), so listing it could let a version range pick it over the real release.
"""

# Comments marked `wire-maven-infra:` depend on how the bucket and CDN are set up, which
# this repository does not control.

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Protocol

GROUP = "com.wire"
# wire-maven-infra: our publishing role may only write keys starting with this prefix.
ALLOWED_PREFIX = "com/wire/core-crypto"
BUCKET = "maven-wire-com"
PUBLIC_URL = "https://maven.wire.com"

METADATA = "maven-metadata.xml"
SIGNATURE_SUFFIX = ".asc"
CHECKSUM_SUFFIXES = (".md5", ".sha1", ".sha256", ".sha512")
# In upload order: Gradle prefers the module file, so it should never find a pom without it.
DESCRIPTOR_SUFFIXES = (".module", ".pom")

# wire-maven-infra: the CDN serves a cached object for up to 60 seconds, so anything that
# waits for S3 and the CDN to agree must keep trying for longer than that.
CDN_PATIENCE_SECONDS = 180


class ReleaseError(Exception):
    """A problem that must stop the command; the message says what went wrong, and where."""


def is_prerelease(version: str) -> bool:
    return "-" in version


def version_key(version: str) -> tuple:
    """Order versions as semver does: numerically, with a pre-release before its release."""

    def identifier(part: str) -> tuple[int, int | str]:
        return (0, int(part)) if part.isdigit() else (1, part)

    release, _, prerelease = version.partition("-")
    return (
        tuple(identifier(part) for part in release.split(".")),
        0 if prerelease else 1,
        tuple(identifier(part) for part in prerelease.split(".")) if prerelease else (),
    )


def is_payload(path: PurePosixPath) -> bool:
    """Whether `path` is a file that needs a signature: neither a signature nor a checksum."""
    return not path.name.endswith((SIGNATURE_SUFFIX, *CHECKSUM_SUFFIXES))


@dataclass
class Artifact:
    artifact_id: str
    # Paths relative to the repository root, all inside this artifact's version directory.
    files: list[PurePosixPath] = field(default_factory=list)


@dataclass
class StagedRepo:
    root: Path
    group: str
    version: str
    artifacts: dict[str, Artifact]

    @property
    def group_path(self) -> PurePosixPath:
        return PurePosixPath(*self.group.split("."))

    def files(self) -> Iterator[PurePosixPath]:
        for artifact in self.artifacts.values():
            yield from artifact.files


def load_repo(root: Path, group: str, version: str, allowed_prefix: str) -> StagedRepo:
    """Read a staged repository, rejecting anything that should not be published from it."""
    group_path = PurePosixPath(*group.split("."))
    artifacts: dict[str, Artifact] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if not relative.as_posix().startswith(allowed_prefix):
            raise ReleaseError(f"{relative} is outside {allowed_prefix}*, where we may not publish")
        if not relative.is_relative_to(group_path):
            raise ReleaseError(f"{relative} is outside the {group} group")
        match relative.relative_to(group_path).parts:
            case (_, name) if name.startswith(METADATA):
                continue
            case (artifact_id, file_version, _):
                if file_version != version:
                    raise ReleaseError(f"{relative} belongs to version {file_version}, not {version}")
                artifacts.setdefault(artifact_id, Artifact(artifact_id)).files.append(relative)
            case _:
                raise ReleaseError(f"{relative} does not fit the Maven repository layout")
    if not artifacts:
        raise ReleaseError(f"{root} holds no artifacts")
    return StagedRepo(root, group, version, artifacts)


def unsigned_files(repo: StagedRepo) -> list[PurePosixPath]:
    present = set(repo.files())
    return [
        path
        for path in repo.files()
        if is_payload(path) and path.with_name(path.name + SIGNATURE_SUFFIX) not in present
    ]


def signed_by(gpg_status: str, key_id: str) -> bool:
    """Whether GnuPG's `--status-fd` output reports a valid signature by `key_id`.

    `key_id` may be a fingerprint or any suffix of one, such as a long or short key id, and
    may name either the signing subkey or its primary key.
    """
    key_id = key_id.upper().removeprefix("0X")
    for line in gpg_status.splitlines():
        fields = line.split()
        if fields[:2] != ["[GNUPG:]", "VALIDSIG"]:
            continue
        # VALIDSIG <signing key fpr> <date> <timestamp> <expiry> <version> <reserved>
        #          <pubkey algo> <hash algo> <class> [<primary key fpr>]
        fingerprints = [fields[2], *fields[11:12]]
        if any(fingerprint.upper().endswith(key_id) for fingerprint in fingerprints):
            return True
    return False


def badly_signed_files(
    repo: StagedRepo,
    key_id: str,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> list[PurePosixPath]:
    bad = []
    for path in filter(is_payload, repo.files()):
        file = repo.root / path
        result = run(
            ["gpg", "--batch", "--status-fd", "1", "--verify", f"{file}{SIGNATURE_SUFFIX}", file],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or not signed_by(result.stdout, key_id):
            bad.append(path)
    return bad


def is_aggregating(repo: StagedRepo, artifact: Artifact) -> bool:
    """Whether the artifact's module file points at variants published by other artifacts."""
    for path in artifact.files:
        if path.suffix == ".module":
            module = json.loads((repo.root / path).read_text())
            if any("available-at" in variant for variant in module.get("variants", [])):
                return True
    return False


def upload_order(repo: StagedRepo) -> list[PurePosixPath]:
    """All files of the repository, in the order described in the module docs."""
    artifacts = sorted(
        repo.artifacts.values(),
        key=lambda artifact: (is_aggregating(repo, artifact), artifact.artifact_id),
    )
    rest = [path for artifact in artifacts for path in artifact.files if path.suffix not in DESCRIPTOR_SUFFIXES]
    descriptors = [
        path
        for artifact in artifacts
        for suffix in DESCRIPTOR_SUFFIXES
        for path in artifact.files
        if path.suffix == suffix
    ]
    return rest + descriptors


def _local_name(element: ET.Element) -> str:
    return element.tag.rpartition("}")[2]


def _child(element: ET.Element | None, name: str) -> ET.Element | None:
    if element is None:
        return None
    return next((child for child in element if _local_name(child) == name), None)


def _text(element: ET.Element | None) -> str | None:
    return element.text.strip() if element is not None and element.text else None


def merge_metadata(
    existing: bytes | None, group: str, artifact_id: str, version: str, now: datetime
) -> bytes | None:
    """`maven-metadata.xml` listing `version` as well, or None if `existing` already lists it.

    `<latest>` and `<release>` both name the highest listed version that is not a
    pre-release. Versions copied by hand from Maven Central may include pre-releases; they
    stay listed, but never win.
    """
    versions: list[str] = []
    if existing is not None:
        root = ET.fromstring(existing)
        found = (_text(_child(root, "groupId")), _text(_child(root, "artifactId")))
        if found != (group, artifact_id):
            raise ReleaseError(f"metadata for {group}:{artifact_id} describes {found[0]}:{found[1]}")
        listed = _child(_child(root, "versioning"), "versions")
        versions = [text for child in ([] if listed is None else listed) if (text := _text(child))]
        if version in versions:
            return None
    versions = sorted({*versions, version}, key=version_key)
    releases = [v for v in versions if not is_prerelease(v)]

    metadata = ET.Element("metadata")
    ET.SubElement(metadata, "groupId").text = group
    ET.SubElement(metadata, "artifactId").text = artifact_id
    versioning = ET.SubElement(metadata, "versioning")
    if releases:
        ET.SubElement(versioning, "latest").text = releases[-1]
        ET.SubElement(versioning, "release").text = releases[-1]
    listed = ET.SubElement(versioning, "versions")
    for v in versions:
        ET.SubElement(listed, "version").text = v
    ET.SubElement(versioning, "lastUpdated").text = now.strftime("%Y%m%d%H%M%S")
    ET.indent(metadata)
    return ET.tostring(metadata, encoding="UTF-8", xml_declaration=True) + b"\n"


class Bucket(Protocol):
    def put(
        self,
        key: str,
        body: Path,
        *,
        if_none_match: bool = False,
        if_match: str | None = None,
        cache_control: str | None = None,
    ) -> bool:
        """Upload `body` to `key`. False if the precondition failed."""
        ...


@dataclass
class Published:
    body: bytes
    etag: str | None


class Cdn(Protocol):
    def get(self, key: str) -> Published | None:
        """The object at `key`, or None if there is none."""
        ...


@dataclass
class S3Bucket:
    """Writes through the AWS CLI, whose `s3api` reports a failed precondition distinctly."""

    name: str
    dry_run: bool = False
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run

    def put(
        self,
        key: str,
        body: Path,
        *,
        if_none_match: bool = False,
        if_match: str | None = None,
        cache_control: str | None = None,
    ) -> bool:
        command = ["aws", "s3api", "put-object", "--bucket", self.name, "--key", key, "--body", str(body)]
        # wire-maven-infra: the bucket refuses any write that does not promise not to
        # overwrite, which is why this never uses `aws s3 sync` or `aws s3 cp`.
        if if_none_match:
            command += ["--if-none-match", "*"]
        if if_match is not None:
            command += ["--if-match", if_match]
        if cache_control is not None:
            command += ["--cache-control", cache_control]
        if self.dry_run:
            print(f"dry run: {shlex.join(command)}")
            return True
        result = self.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            return True
        # 412 means the precondition failed; 409 that a concurrent conditional write to the
        # same key won. Either way, the caller should look at what is there now.
        if "PreconditionFailed" in result.stderr or "ConditionalRequestConflict" in result.stderr:
            return False
        raise ReleaseError(f"uploading {key} failed: {result.stderr.strip()}")


@dataclass
class HttpCdn:
    # wire-maven-infra: our publishing role may lack s3:GetObject, so all reads go through
    # the public CDN instead. That only works because a missing key gets a 404, not a 403.
    base_url: str

    def get(self, key: str) -> Published | None:
        # No Accept-Encoding header: a compressed response would carry a weak ETag, which
        # S3 cannot match.
        try:
            with urllib.request.urlopen(f"{self.base_url}/{key}", timeout=30) as response:
                return Published(response.read(), response.headers.get("ETag"))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise ReleaseError(f"reading {key} from {self.base_url} failed: {error}") from error


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Release:
    repo: StagedRepo
    bucket: Bucket
    cdn: Cdn
    key_prefix: str = ""
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def run(self) -> None:
        for path in upload_order(self.repo):
            self.upload(path)
        if is_prerelease(self.repo.version):
            print(f"{self.repo.version} is a pre-release, so no maven-metadata.xml will list it")
            return
        for artifact_id in sorted(self.repo.artifacts):
            self.list_version(artifact_id)

    def key(self, path: PurePosixPath) -> str:
        return self.key_prefix + path.as_posix()

    def patiently(self, give_up: str) -> Iterator[None]:
        """Yield once per attempt, with growing pauses, until the CDN must have caught up."""
        deadline = self.clock() + CDN_PATIENCE_SECONDS
        delay = 2.0
        while True:
            yield
            if self.clock() + delay > deadline:
                raise ReleaseError(give_up)
            self.sleep(delay)
            delay = min(delay * 2, 30.0)

    def upload(self, path: PurePosixPath) -> None:
        key = self.key(path)
        file = self.repo.root / path
        if self.bucket.put(key, file, if_none_match=True):
            print(f"uploaded {key}")
            return
        # The key exists already: an earlier attempt at this release got this far, or this
        # version was published before from different content.
        expected = sha256(file.read_bytes())
        for _ in self.patiently(f"{key} exists in the bucket, but the CDN never served it"):
            published = self.cdn.get(key)
            if published is None:
                # The CDN still caches an earlier 404.
                continue
            if sha256(published.body) != expected:
                raise ReleaseError(
                    f"{key} is already published with different content; published versions"
                    " are immutable, so release this as a new version instead"
                )
            print(f"already uploaded {key}")
            return

    def list_version(self, artifact_id: str) -> None:
        key = self.key(self.repo.group_path / artifact_id / METADATA)
        for _ in self.patiently(f"{key} kept changing, or the CDN kept serving a stale copy"):
            current = self.cdn.get(key)
            merged = merge_metadata(
                current.body if current else None,
                self.repo.group,
                artifact_id,
                self.repo.version,
                self.now(),
            )
            if merged is None:
                print(f"{key} already lists {self.repo.version}")
                return
            if current is not None and (current.etag is None or current.etag.startswith("W/")):
                raise ReleaseError(f"{key} came without a strong ETag, so it cannot be updated safely")
            with tempfile.NamedTemporaryFile(suffix=".xml") as body:
                body.write(merged)
                body.flush()
                # wire-maven-infra: maven-metadata.xml is the only key the bucket lets us
                # overwrite. Its checksum files would go stale, so we publish none for it.
                # `no-cache` asks the CDN to revalidate it, so new versions show up promptly.
                written = self.bucket.put(
                    key,
                    Path(body.name),
                    if_none_match=current is None,
                    if_match=current.etag if current else None,
                    cache_control="no-cache",
                )
            if written:
                print(f"listed {self.repo.version} in {key}")
                return
            # Another release updated the file first, or the CDN served a stale copy: read
            # it again and merge anew.


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add_command(name: str, summary: str) -> argparse.ArgumentParser:
        command = commands.add_parser(name, help=summary)
        command.add_argument("repo", type=Path, help="the staged Maven repository")
        command.add_argument("--version", required=True, help="the version being published")
        command.add_argument("--group", default=GROUP, help="the Maven group id (default: %(default)s)")
        command.add_argument(
            "--allowed-prefix",
            default=ALLOWED_PREFIX,
            help="every path in REPO must start with this (default: %(default)s)",
        )
        return command

    verify = add_command("verify", "check a staged repository before it is released")
    verify.add_argument("--key-id", help="require valid signatures by this key")
    verify.add_argument(
        "--expect-artifact",
        action="append",
        default=[],
        metavar="ARTIFACT_ID",
        help="require exactly these artifacts (repeatable)",
    )

    release = add_command("release", "upload a staged repository to S3")
    release.add_argument("--bucket", default=BUCKET, help="the S3 bucket (default: %(default)s)")
    release.add_argument("--key-prefix", default="", help="prepended to every S3 key")
    release.add_argument(
        "--public-url",
        default=PUBLIC_URL,
        help="where the bucket is served (default: %(default)s)",
    )
    release.add_argument("--dry-run", action="store_true", help="print uploads instead of making them")

    args = parser.parse_args(argv)
    HTTPS="https://"
    if not args.public_url.startswith(HTTPS):
        raise ValueError(f"--public-url value must start with '{HTTPS}'")
    try:
        repo = load_repo(args.repo, args.group, args.version, args.allowed_prefix)
        if unsigned := unsigned_files(repo):
            raise ReleaseError("unsigned: " + ", ".join(map(str, unsigned)))
        if args.command == "verify":
            if args.expect_artifact and set(args.expect_artifact) != set(repo.artifacts):
                raise ReleaseError(
                    f"expected artifacts {sorted(args.expect_artifact)}, found {sorted(repo.artifacts)}"
                )
            if args.key_id and (bad := badly_signed_files(repo, args.key_id)):
                raise ReleaseError(f"not validly signed by {args.key_id}: " + ", ".join(map(str, bad)))
            print(f"verified {len(list(repo.files()))} files in {sorted(repo.artifacts)}")
        else:
            bucket = S3Bucket(args.bucket, dry_run=args.dry_run)
            cdn = HttpCdn(args.public_url.rstrip("/"))
            Release(repo, bucket, cdn, key_prefix=args.key_prefix).run()
    except ReleaseError as error:
        # The `::error::` prefix makes GitHub Actions annotate the run with the message.
        print(f"::error::{error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
