#!/usr/bin/env bash
# setup-ec2.sh — one-time setup for a fresh Amazon Linux 2023 / Ubuntu EC2 instance
#
# Run as ec2-user (Amazon Linux) or ubuntu (Ubuntu) with sudo access.
# After this script completes, the instance is ready for:
#   ./scripts/fetch-secrets.sh
#   docker-compose -f docker-compose.prod.yml up -d

set -euo pipefail

echo "=== Multi-Agent Compliance Platform — EC2 Setup ==="
echo "Detected OS: $(uname -a)"

# ── 1. System update ─────────────────────────────────────────────────────────
if command -v yum &>/dev/null; then
    sudo yum update -y
    PKG="yum"
elif command -v apt-get &>/dev/null; then
    sudo apt-get update -y
    PKG="apt"
else
    echo "Unsupported package manager" >&2; exit 1
fi

# ── 2. Docker ────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "Installing Docker..."
    if [ "$PKG" = "yum" ]; then
        sudo yum install -y docker
        sudo systemctl enable --now docker
    else
        sudo apt-get install -y ca-certificates curl
        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
            | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update -y
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io
        sudo systemctl enable --now docker
    fi
    sudo usermod -aG docker "$USER"
    echo "Docker installed. You will need to log out and back in for group membership."
fi

# ── 3. Docker Compose v2 ────────────────────────────────────────────────────
if ! docker compose version &>/dev/null; then
    echo "Installing Docker Compose plugin..."
    COMPOSE_VERSION="v2.27.1"
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    sudo curl -SL \
        "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" \
        -o /usr/local/lib/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi

echo "Docker Compose: $(docker compose version)"

# ── 4. AWS CLI v2 ───────────────────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
    echo "Installing AWS CLI v2..."
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp
    sudo /tmp/aws/install
    rm -rf /tmp/awscliv2.zip /tmp/aws
fi
echo "AWS CLI: $(aws --version)"

# ── 5. ECR login helper (uses instance role — no static creds needed) ────────
echo "Configuring ECR credential helper..."
if [ "$PKG" = "yum" ]; then
    sudo yum install -y amazon-ecr-credential-helper 2>/dev/null || true
elif [ "$PKG" = "apt" ]; then
    sudo apt-get install -y amazon-ecr-credential-helper 2>/dev/null || true
fi

mkdir -p ~/.docker
if [ ! -f ~/.docker/config.json ]; then
    echo '{"credsStore": "ecr-login"}' > ~/.docker/config.json
fi

# ── 6. Project directory ─────────────────────────────────────────────────────
APP_DIR="/opt/compliance-platform"
sudo mkdir -p "$APP_DIR"
sudo chown "$USER:$USER" "$APP_DIR"
echo "App directory: $APP_DIR"
echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Clone the repo:  git clone <repo-url> $APP_DIR"
echo "  2. Fetch secrets:   cd $APP_DIR && ./scripts/fetch-secrets.sh"
echo "  3. Set ECR_IMAGE:   export ECR_IMAGE=<account>.dkr.ecr.<region>.amazonaws.com/compliance:latest"
echo "  4. Start services:  docker compose -f docker-compose.prod.yml up -d"
