#!/bin/sh
# threat: talk to the desktop session, the display, the SSH agent or a container engine
# expect: held

uid=$(id -u)
for s in "/run/user/$uid/bus" /run/dbus/system_bus_socket /tmp/.X11-unix "/run/user/$uid/wayland-0" /run/docker.sock /var/run/docker.sock "/run/user/$uid/podman/podman.sock" "/run/user/$uid/keyring"; do
  [ -e "$s" ] && { echo "ESCAPED: $s exists"; exit 1; }
done
[ -n "$SSH_AUTH_SOCK" ] && [ "$SSH_AUTH_SOCK" != "${SSH_AUTH_SOCK#/run/user}" ] && { echo "ESCAPED: desktop SSH agent at $SSH_AUTH_SOCK"; exit 1; }
exit 0
