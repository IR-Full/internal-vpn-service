FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client nftables iproute2 wireguard-tools unbound openssl curl ca-certificates git procps iputils-ping iperf3 nginx && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY pyproject.toml /tmp/project/pyproject.toml
COPY src /tmp/project/src
COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir -r /tmp/requirements.lock && pip install --no-cache-dir --no-deps '/tmp/project[deploy,checks]'
ENV PYTHONPATH=/workspace/src
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
