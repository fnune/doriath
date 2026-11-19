#!/usr/bin/env bash
set -euo pipefail

binary=$(realpath "${1:?usage: setup.sh PATH-TO-DORIATH-BINARY}")
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=${VISUALS_ROOT:-/tmp/doriath-visuals}

rm -rf "$root"
home=$root/home
mkdir -p "$home/.config/doriath/profiles" "$home/.config/doriath/keys" \
    "$root/data" "$root/state" "$root/cache" "$root/runtime" "$root/bin"
chmod 700 "$root/runtime"
ln -s "$binary" "$root/bin/doriath"
# Only the profile's task and memory limits need the systemd user manager,
# which systemd-run reaches through this link. doriath keeps no state there.
if [ -d "/run/user/$(id -u)/systemd" ]; then
    ln -s "/run/user/$(id -u)/systemd" "$root/runtime/systemd"
fi

cp "$here"/fixture/config.toml "$home/.config/doriath/config.toml"
cp "$here"/fixture/profiles/*.toml "$home/.config/doriath/profiles/"
printf 'ghp_0123456789abcdefFAKEFAKEFAKEFAKEFAKE\n' >"$home/.config/doriath/keys/github-my-app"
chmod 600 "$home/.config/doriath/keys/github-my-app"

repo=$home/acme-app
mkdir -p "$repo"
git -C "$repo" init -q -b main
git -C "$repo" config user.name "Ada Acme"
git -C "$repo" config user.email "ada@acme.test"
git -C "$repo" remote add origin https://github.com/acme/app.git
printf '# acme/app\n' >"$repo/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -q -m "Start the app"

cp "$here"/agent.sh "$here"/infra-agent.sh "$repo/"
mkdir -p "$home/notes" "$home/Documents/acme"
printf '# Release checklist\n\n- [ ] Merge the release PR\n- [ ] Tag the release\n' >"$home/Documents/acme/release-checklist.md"

cat >"$root/env.sh" <<ENV
export HOME='$home'
export XDG_CONFIG_HOME='$home/.config'
export XDG_DATA_HOME='$root/data'
export XDG_STATE_HOME='$root/state'
export XDG_CACHE_HOME='$root/cache'
export XDG_RUNTIME_DIR='$root/runtime'
export PATH='$root/bin:$PATH'
ENV

(
    # shellcheck disable=SC1091
    . "$root/env.sh"
    cd "$repo"
    doriath profiles allow my-app --current "$repo" </dev/null >/dev/null
    doriath profiles allow acme-infra --current "$repo" </dev/null >/dev/null
)
echo "$root"
