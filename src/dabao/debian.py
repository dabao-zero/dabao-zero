"""Debian DistroAdapter (PLAN S4, ADR-0004): rebuild one source package with a patch.

The unpatched build is the official image itself. A patched build runs `docker buildx build` with a
generated Dockerfile that, from the pinned base image and a snapshot.debian.org archive of the same
date, fetches the source package at the vulnerable version, applies the patch (a rejected hunk
fails the build), rebuilds the .debs with a fixed SOURCE_DATE_EPOCH, installs those the base image
already has, and writes an OCI layout with rewritten timestamps. Same inputs give the same digest.

`Component.package` is the Debian *source* package name. Docker runs through an injectable runner
so unit tests need no daemon and no network.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path

from dabao.buildx import (
    BuildError,
    Runner,
    build_oci,
    check_debian_version,
    check_name,
    default_runner,
)
from dabao.models import Component, Patch

LOCAL_SUFFIX = "+dabao1"


class DebianBuildError(BuildError):
    pass


@dataclass(frozen=True)
class DebianBase:
    """The official image a stream is built on, pinned so a build can be replayed."""

    image: str  # tag, for humans: debian:bookworm-20240110-slim
    digest: str  # sha256:... of that image; the build starts FROM it
    snapshot: str  # snapshot.debian.org timestamp matching the image, e.g. 20240110T000000Z
    source_date_epoch: int
    suite: str = "bookworm"


def changelog_entry(component: Component, patch: Patch, base: DebianBase) -> str:
    stamp = format_datetime(datetime.fromtimestamp(base.source_date_epoch, UTC))
    return (
        f"{component.package} ({component.version}{LOCAL_SUFFIX}) {base.suite}; urgency=medium\n\n"
        f"  * dabao-zero: backport the upstream fix for {patch.advisory_id}\n"
        f"    ({patch.upstream_ref})\n\n"
        f" -- dabao-zero <dabao-zero@users.noreply.github.com>  {stamp}\n\n"
    )


def render_dockerfile(component: Component, base: DebianBase) -> str:
    pin = f"{component.package}={component.version}"
    snap = f"http://snapshot.debian.org/archive/debian/{base.snapshot}/"
    sec = f"http://snapshot.debian.org/archive/debian-security/{base.snapshot}/"
    sources = (
        f"Types: deb deb-src\\nURIs: {snap}\\nSuites: {base.suite}\\nComponents: main\\n"
        f"Check-Valid-Until: no\\n\\n"
        f"Types: deb deb-src\\nURIs: {sec}\\nSuites: {base.suite}-security\\nComponents: main\\n"
        f"Check-Valid-Until: no\\n"
    )
    return f"""FROM {base.image}@{base.digest} AS build
ARG SOURCE_DATE_EPOCH
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eu; \\
    rm -f /etc/apt/sources.list; \\
    printf '{sources}' > /etc/apt/sources.list.d/debian.sources; \\
    apt-get update; \\
    apt-get install -y --no-install-recommends build-essential fakeroot dpkg-dev; \\
    apt-get build-dep -y --no-install-recommends {pin}
WORKDIR /build
RUN set -eu; apt-get source --download-only {pin}; dpkg-source -x ./*.dsc src
COPY patch.diff changelog.entry /ctx/
RUN set -eu; cd src; \\
    patch -p1 --no-backup-if-mismatch < /ctx/patch.diff; \\
    cat /ctx/changelog.entry debian/changelog > /tmp/changelog; mv /tmp/changelog debian/changelog
RUN set -eu; useradd --create-home --uid 1000 builder; chown -R builder:builder /build; \\
    runuser -u builder -- env SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \\
      DEB_BUILD_OPTIONS="nocheck parallel=$(nproc)" \\
      sh -c 'cd src && dpkg-buildpackage -b -uc -us'; \\
    mkdir /out; cp ./*.deb /out/

FROM {base.image}@{base.digest}
COPY --from=build /out/ /tmp/dabao-debs/
RUN set -eu; cd /tmp/dabao-debs; keep=""; \\
    for d in *.deb; do \\
      n=$(dpkg-deb -f "$d" Package); \\
      st=$(dpkg-query -W -f='${{Status}}' "$n" 2>/dev/null || true); \\
      if [ "$st" = "install ok installed" ]; then keep="$keep ./$d"; fi; \\
    done; \\
    [ -n "$keep" ] || {{ echo "no rebuilt package is in the base image" >&2; exit 1; }}; \\
    dpkg --log=/dev/null -i $keep || dpkg --log=/dev/null -i $keep; \\
    cd /; rm -rf /tmp/dabao-debs; rm -f /var/log/alternatives.log
"""


@dataclass
class DebianAdapter:
    base: DebianBase
    work_dir: Path
    runner: Runner = default_runner
    builder: str = "dabao-builder"  # a buildx builder with the docker-container driver
    archives: dict[str, Path] = field(default_factory=dict)  # digest -> OCI layout directory

    def build_image(self, component: Component, patch: Patch | None) -> str:
        if patch is None:
            return self.base.digest
        if component.stream != "debian":
            raise ValueError(f"the debian adapter cannot build the {component.stream} stream")
        if patch.component != component:
            raise ValueError("patch does not match the component being built")
        check_name(component.package)
        check_debian_version(component.version)
        key = hashlib.sha256(
            json.dumps(
                [component.model_dump(), patch.diff, self.base.digest, self.base.snapshot]
            ).encode()
        ).hexdigest()[:16]
        root = self.work_dir / key
        ctx, out = root / "ctx", root / "oci"
        ctx.mkdir(parents=True, exist_ok=True)
        (ctx / "Dockerfile").write_text(render_dockerfile(component, self.base))
        (ctx / "patch.diff").write_text(patch.diff)
        (ctx / "changelog.entry").write_text(changelog_entry(component, patch, self.base))
        try:
            digest = build_oci(self.runner, self.builder, ctx, out, self.base.source_date_epoch)
        except BuildError as exc:
            raise DebianBuildError(str(exc)) from exc
        self.archives[digest] = out
        return digest
