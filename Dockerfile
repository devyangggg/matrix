# Matrix builder / CLI image (development). See docs/LLD.md §12.2.
# Builds themselves run in the pinned Go image from genesis, on the host Docker daemon.
FROM python:3.11-slim

# Docker CLI only (the daemon is the host's, reached through the mounted socket).
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY matrix ./matrix
RUN pip install --no-cache-dir .

# Containers run as an arbitrary host uid; give git and Python a writable HOME.
ENV HOME=/tmp PYTHONUNBUFFERED=1
EXPOSE 7700
CMD ["matrix-node", "--help"]
