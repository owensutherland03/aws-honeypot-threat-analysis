#!/bin/bash
# EC2 user data: runs once, as root, on the instance's first boot.
#
# Port 22 will belong to the honeypot (Phase 3), and admin access is via
# SSM Session Manager, so the real OpenSSH server is turned off and masked
# (masking stops anything from re-enabling it, including socket activation).
set -euo pipefail
systemctl disable --now ssh.socket ssh.service || true
systemctl mask ssh.socket ssh.service
