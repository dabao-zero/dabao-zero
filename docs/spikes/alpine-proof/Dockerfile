# DAB-75 spike: rebuild Alpine's own brotli recipe at the version that fixes CVE-2026-111497, and put it
# into the stock nginx:alpine image. Not the adapter (DAB-30); a throwaway proof.
FROM mirror.gcr.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS build
RUN apk update && apk add alpine-sdk git sudo python3 \
 && adduser -D builder && addgroup builder abuild \
 && echo '%abuild ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/abuild
USER builder
WORKDIR /home/builder
RUN abuild-keygen -a -n -q && sudo cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/
RUN git clone -q --depth 1 --filter=blob:none --sparse --branch 3.24-stable \
      https://gitlab.alpinelinux.org/alpine/aports.git \
 && cd aports && git sparse-checkout set main/brotli
WORKDIR /home/builder/aports/main/brotli
# the full recipe, including the python subpackage and its tests
RUN set -o pipefail 2>/dev/null; abuild -r > /tmp/abuild.log 2>&1 || { tail -30 /tmp/abuild.log; exit 1; }; tail -3 /tmp/abuild.log
USER root
RUN mkdir /out && cp /home/builder/packages/main/*/brotli-libs-*.apk /out/ \
 && cp /home/builder/.abuild/*.rsa.pub /out/

FROM mirror.gcr.io/library/nginx@sha256:a3554c0d0b48177b1413c26e01f695334428020d9df01243fbae3e11cfd17417
COPY --from=build /out/ /tmp/dabao-apk/
# the signature names the key by file name, so the key keeps its name; it is removed again after the install
RUN cp /tmp/dabao-apk/*.rsa.pub /etc/apk/keys/ \
 && apk add --no-cache /tmp/dabao-apk/brotli-libs-*.apk \
 && rm -rf /tmp/dabao-apk /etc/apk/keys/builder-*.rsa.pub
