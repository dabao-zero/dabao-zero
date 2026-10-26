"""Alpine DistroAdapter (PLAN S4, ADR-0004, ADR-0011): rebuild one aport with a patch.

The unpatched build is the official image itself. A patched build runs `docker buildx build` with
a generated Dockerfile that, in a pinned Alpine builder: finds the aports commit whose recipe is
exactly the vulnerable version, adds the patch as a source of the recipe with a fresh checksum and
the next revision (`-r1` becomes `-r2`), checks the recipe really applies it, builds with `abuild`
as a normal user, and installs the packages the base image already has. Packages are mounted from
the build stage (never copied into a layer), lose their per-build signature, and are installed
untrusted, so no key is ever in the image; `/etc/apk/world` and the apk log are put back as they
were. The build adds one layer.

`Component.package` is the aport (origin) name and `Component.version` is `pkgver-rN`. Docker runs
through an injectable runner so unit tests need no daemon and no network.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from dabao.buildx import (
    BuildError,
    Runner,
    build_oci,
    check_apk_version,
    check_name,
    default_runner,
)
from dabao.models import Component, Patch

APORTS_URL = "https://gitlab.alpinelinux.org/alpine/aports.git"
HISTORY_DEPTH = 400  # commits of one recipe to search for the vulnerable version


class AlpineBuildError(BuildError):
    pass


@dataclass(frozen=True)
class AlpineBase:
    """The official image a stream is built on, and the builder that matches its release."""

    image: str  # tag, for humans: nginx:alpine
    digest: str  # sha256:... of that image; the build ends FROM it
    builder_image: str  # alpine:3.24, the same release as the base
    builder_digest: str
    release: str  # 3.24; aports branch is `<release>-stable`
    source_date_epoch: int


def rebuilt_version(version: str) -> str:
    """`1.2.0-r1` -> `1.2.0-r2`: the next revision of the same upstream version."""
    m = re.match(r"^(.*)-r(\d+)$", version)
    if m is None:
        raise ValueError(f"version has no revision (-rN): {version!r}")
    return f"{m.group(1)}-r{int(m.group(2)) + 1}"


def render_dockerfile(component: Component, base: AlpineBase) -> str:
    pkg, want = component.package, component.version
    newver = rebuilt_version(want)
    newrel = newver.rsplit("-r", 1)[1]
    return f"""FROM {base.builder_image}@{base.builder_digest} AS build
ARG SOURCE_DATE_EPOCH
RUN set -eu; apk update; apk add alpine-sdk git sudo python3; \\
    adduser -D builder; addgroup builder abuild; \\
    echo '%abuild ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/abuild
USER builder
WORKDIR /home/builder
RUN set -eu; abuild-keygen -a -n -q; sudo cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/
RUN set -eu; git clone -q --filter=blob:none --no-checkout --branch {base.release}-stable {APORTS_URL}; \\
    cd aports; git sparse-checkout init --cone; git sparse-checkout set main/{pkg} community/{pkg}
RUN set -eu; cd aports; WANT="{want}"; found=""; \\
    for c in $(git log --format=%H -n {HISTORY_DEPTH} -- main/{pkg}/APKBUILD community/{pkg}/APKBUILD); do \\
      for r in main community; do \\
        git show "$c:$r/{pkg}/APKBUILD" > /tmp/probe 2>/dev/null || continue; \\
        ver="$(sed -n 's/^pkgver=//p' /tmp/probe | head -1 | tr -d "\\"'")"; \\
        rel="$(sed -n 's/^pkgrel=//p' /tmp/probe | head -1 | tr -d "\\"'")"; \\
        if [ "$ver-r$rel" = "$WANT" ]; then \\
          git checkout -q "$c" -- "$r/{pkg}"; echo "$r" > /tmp/repo; found=1; break 2; \\
        fi; \\
      done; \\
    done; \\
    [ -n "$found" ] || {{ echo "no aports commit has {pkg} $WANT" >&2; exit 1; }}
COPY patch.diff /tmp/patch.diff
RUN set -eu; cd aports/$(cat /tmp/repo)/{pkg}; \\
    cp /tmp/patch.diff dabao-fix.patch; \\
    printf '\\nsource="$source dabao-fix.patch"\\npkgrel={newrel}\\n' >> APKBUILD; \\
    abuild checksum; \\
    abuild unpack prepare; \\
    set -- src/*/; cd "$1"; patch -R -p1 --dry-run < ../../dabao-fix.patch
RUN set -eu; cd aports/$(cat /tmp/repo)/{pkg}; \\
    abuild -r > /tmp/abuild.log 2>&1 || {{ tail -40 /tmp/abuild.log; exit 1; }}
USER root
# An apk is three gzip members: signature, control, data. Control and data are byte-identical between
# builds; the signature is not (a new key every build), so it is dropped and the install is untrusted.
RUN set -eu; mkdir /out; for f in /home/builder/packages/$(cat /tmp/repo)/*/*.apk; do \\
      python3 -c "import sys,zlib; d=zlib.decompressobj(31); d.decompress(open(sys.argv[1],'rb').read()); open(sys.argv[2],'wb').write(d.unused_data)" "$f" "/out/$(basename "$f")"; \\
    done

FROM {base.image}@{base.digest}
RUN --mount=type=bind,from=build,source=/out,target=/tmp/dabao-apk \\
    set -eu; cd /tmp/dabao-apk; cp /etc/apk/world /tmp/world.keep; \\
    if [ -f /var/log/apk.log ]; then cp /var/log/apk.log /tmp/apk.log.keep; fi; keep=""; \\
    for f in *.apk; do \\
      n="${{f%-{newver}.apk}}"; \\
      if apk info -e "$n" >/dev/null 2>&1; then keep="$keep ./$f"; fi; \\
    done; \\
    [ -n "$keep" ] || {{ echo "no rebuilt package is in the base image" >&2; exit 1; }}; \\
    apk add --no-cache --allow-untrusted $keep; \\
    cp /tmp/world.keep /etc/apk/world; \\
    if [ -f /tmp/apk.log.keep ]; then cp /tmp/apk.log.keep /var/log/apk.log; else rm -f /var/log/apk.log; fi; \\
    rm -f /tmp/world.keep /tmp/apk.log.keep
"""  # noqa: E501


@dataclass
class AlpineAdapter:
    base: AlpineBase
    work_dir: Path
    runner: Runner = default_runner
    builder: str = "dabao-builder"  # a buildx builder with the docker-container driver
    archives: dict[str, Path] = field(default_factory=dict)  # digest -> OCI layout directory

    def build_image(self, component: Component, patch: Patch | None) -> str:
        if patch is None:
            return self.base.digest
        if component.stream != "alpine":
            raise ValueError(f"the alpine adapter cannot build the {component.stream} stream")
        if patch.component != component:
            raise ValueError("patch does not match the component being built")
        check_name(component.package)
        check_apk_version(component.version)
        key = hashlib.sha256(
            json.dumps(
                [component.model_dump(), patch.diff, self.base.digest, self.base.builder_digest]
            ).encode()
        ).hexdigest()[:16]
        root = self.work_dir / key
        ctx, out = root / "ctx", root / "oci"
        ctx.mkdir(parents=True, exist_ok=True)
        (ctx / "Dockerfile").write_text(render_dockerfile(component, self.base))
        (ctx / "patch.diff").write_text(patch.diff)
        try:
            digest = build_oci(self.runner, self.builder, ctx, out, self.base.source_date_epoch)
        except BuildError as exc:
            raise AlpineBuildError(str(exc)) from exc
        self.archives[digest] = out
        return digest
