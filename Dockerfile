# ossys — container image
#
# Purpose: a disposable sandbox for the destructive commands. `ossys useradd` mutates
#          /etc/passwd; doing that inside a throwaway container means experimenting with
#          user provisioning without touching a real host, and gives CI somewhere safe to
#          exercise the privileged code path for real instead of against mocks.
#
# Build:   docker build -t ossys:local .
#
# Run — UNPRIVILEGED path (the default; matches `mode = "user"`):
#          docker run --rm ossys:local check
#          docker run --rm -v "$PWD:/work" -w /work ossys:local archive a.log -o out.tgz
#
# Run — PRIVILEGED path (root inside the container; the container is the boundary):
#          docker run --rm --user root ossys:local --mode root useradd alice --sudo
#
# The image deliberately does NOT default to root. Least privilege is the same principle
# applied everywhere else in this project — sudo-group membership is opt-in, elevation is
# detected rather than assumed — and a root-by-default image is a loaded gun the moment
# somebody adds `-v /:/host`. Opting in is one flag; opting out after an incident is not.

# --- Stage 1: build the wheel ---------------------------------------------------------------
# Pinned to a minor version. For a production image pin by digest instead
# (python:3.12-slim-bookworm@sha256:...) so a rebuild cannot silently pick up a new base.
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

# Copy only what the build needs, so editing a test does not invalidate the dependency layer.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# --no-isolation is deliberate: `build` otherwise creates a fresh venv and re-downloads the
# backend, ignoring the hatchling installed on the line above. That means an extra network
# fetch on every build and a backend version nobody pinned.
RUN python -m pip install --no-cache-dir build hatchling \
    && python -m build --wheel --no-isolation --outdir /dist


# --- Stage 2: runtime -------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# OCI metadata — makes the image self-describing to scanners and registries.
LABEL org.opencontainers.image.title="ossys" \
      org.opencontainers.image.description="Hardened, automatable Linux admin CLI" \
      org.opencontainers.image.source="https://github.com/www8351/Linux-Hardening-and-System" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# `passwd` supplies useradd/usermod. Debian slim already ships them, but naming the package
# explicitly means a base-image change that drops them fails the build here rather than
# producing an image where `ossys useradd` reports "required tool not found on PATH" at
# runtime. `ossys check` verifies the same thing from the other side.
RUN apt-get update \
    && apt-get install -y --no-install-recommends passwd \
    && rm -rf /var/lib/apt/lists/*

# Install from the built wheel: no build toolchain, no pip cache, no source tree in the
# final image. Smaller attack surface and nothing to compile at runtime.
COPY --from=builder /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Config lives where the privileged discovery path looks for it, so a mounted
# /etc/ossys/ossys.toml is picked up with no flags:
#     docker run --rm -v "$PWD/ossys.toml:/etc/ossys/ossys.toml:ro" ossys:local check
RUN mkdir -p /etc/ossys /var/lib/ossys

# Unprivileged identity for the default path. 10001 is outside the range Debian's adduser
# hands out, so an `ossys useradd` run inside the container cannot collide with it.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin ossys \
    && chown ossys:ossys /var/lib/ossys

USER ossys
WORKDIR /home/ossys

# No HEALTHCHECK: ossys is a one-shot command, not a service. There is no process to probe,
# and a HEALTHCHECK on a container that exits immediately is noise. The equivalent signal is
# `docker run --rm ossys:local check --strict`, which exits 60 when the host is unfit.

ENTRYPOINT ["ossys"]
CMD ["check"]
