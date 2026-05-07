FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PATH="/home/researcher/.local/bin:/opt/codeql:/usr/local/go/bin:${PATH}"

# ── system ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq unzip xz-utils \
        gnupg lsb-release \
        python3.12 python3.12-venv python3-pip pipx \
        build-essential pkg-config \
        ripgrep fd-find \
        tmux openssh-client \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3.12 /usr/local/bin/python3 \
    && ln -sf /usr/bin/python3.12 /usr/local/bin/python

# ── node 22 (for openrig + claude code + codex) ───────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/*

# ── trivy ─────────────────────────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── grype ─────────────────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── osv-scanner (arch-aware) ──────────────────────────────────────────
RUN ARCH=$(dpkg --print-architecture) \
 && case "$ARCH" in \
        amd64) OSV_ARCH=amd64 ;; \
        arm64) OSV_ARCH=arm64 ;; \
        *) echo "unsupported arch $ARCH" && exit 1 ;; \
    esac \
 && curl -sSL "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${OSV_ARCH}" \
        -o /usr/local/bin/osv-scanner \
 && chmod +x /usr/local/bin/osv-scanner

# ── gitleaks (arch-aware) ─────────────────────────────────────────────
RUN ARCH=$(dpkg --print-architecture) \
 && case "$ARCH" in \
        amd64) GL_ARCH=x64 ;; \
        arm64) GL_ARCH=arm64 ;; \
        *) echo "unsupported arch $ARCH" && exit 1 ;; \
    esac \
 && GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name | sed 's/^v//') \
 && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks \
 && chmod +x /usr/local/bin/gitleaks

# ── (optional) codeql cli — heavy, ~500MB; uncomment if wanted ────────
# RUN curl -sSL https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
#         -o /tmp/codeql.zip \
#     && unzip /tmp/codeql.zip -d /opt/ \
#     && rm /tmp/codeql.zip

# ── user ──────────────────────────────────────────────────────────────
# Ubuntu 24.04 ships with a default `ubuntu` user at uid 1000 — drop it.
RUN userdel -r ubuntu 2>/dev/null || true \
 && useradd -m -s /bin/bash -u 1000 researcher \
 && echo "researcher ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/researcher \
 && mkdir -p /work /auth \
 && chown -R researcher:researcher /work /auth

USER researcher
WORKDIR /home/researcher

# ── python tools (user-scoped via pipx) ───────────────────────────────
RUN pipx ensurepath \
 && pipx install depenemy \
 && pipx install semgrep

# ── node tools (user-scoped npm prefix) ───────────────────────────────
ENV NPM_CONFIG_PREFIX=/home/researcher/.npm-global \
    PATH="/home/researcher/.npm-global/bin:${PATH}"
RUN mkdir -p $NPM_CONFIG_PREFIX \
 && npm install -g \
        @openrig/cli \
        @anthropic-ai/claude-code \
        @openai/codex

# ── investigate CLI ───────────────────────────────────────────────────
COPY --chown=researcher:researcher investigate /usr/local/bin/investigate
RUN sudo chmod +x /usr/local/bin/investigate

# ── prompts (used by synthesis pass) ──────────────────────────────────
COPY --chown=researcher:researcher prompts /home/researcher/prompts

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/investigate"]
CMD ["--help"]
