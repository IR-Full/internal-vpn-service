FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
# Patch the acquisition backend before allowing retries (CVE-2026-109518).
RUN set -eu; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Retries=0 -o APT::Update::Error-Mode=any update; \
    apt-get -o Acquire::Retries=0 install -y --no-install-recommends --only-upgrade apt libapt-pkg6.0; \
    for package in apt libapt-pkg6.0; do \
      dpkg --compare-versions "$(dpkg-query -W -f='${Version}' "$package")" ge 2.6.2; \
    done; \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends openssh-client nftables iproute2 wireguard-tools unbound openssl curl ca-certificates git procps iputils-ping iperf3 nginx; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY pyproject.toml /tmp/project/pyproject.toml
COPY src /tmp/project/src
COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir -r /tmp/requirements.lock && pip install --no-cache-dir --no-deps '/tmp/project[deploy,checks]'
ENV PYTHONPATH=/workspace/src
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
