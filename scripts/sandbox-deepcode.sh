#!/bin/bash

# The exact directory you want to give access to
PROJECT_DIR="/run/media/oliveira/Disco A/mikrotik-dashboard"

# Ensure the directory exists
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Directory does not exist: $PROJECT_DIR"
    exit 1
fi

echo "Starting sandboxed shell..."
echo "Only $PROJECT_DIR is writable. Everything else is read-only or hidden."
echo "You are inside a user namespace, so 'sudo' will not work."

# Launch bubblewrap
exec bwrap \
    --ro-bind /usr /usr \
    --ro-bind /lib /lib \
    --ro-bind /lib64 /lib64 \
    --ro-bind /bin /bin \
    --ro-bind /sbin /sbin \
    --ro-bind /etc/resolv.conf /etc/resolv.conf \
    --ro-bind /etc/hosts /etc/hosts \
    --ro-bind /etc/nsswitch.conf /etc/nsswitch.conf \
    --ro-bind /etc/ssl /etc/ssl \
    --bind "$PROJECT_DIR" "$PROJECT_DIR" \
    --tmpfs /tmp \
    --tmpfs /var/tmp \
    --proc /proc \
    --dev /dev \
    --unshare-all \
    --share-net \
    --cap-drop ALL \
    --chdir "$PROJECT_DIR" \
    /bin/bash
