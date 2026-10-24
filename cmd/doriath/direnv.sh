# doriath's direnv library. In .envrc at a project's root:
#
#   use doriath PROFILE [PROFILE...] [--command NAME]
#
# puts a shim for NAME first on PATH, so that running it
# anywhere in the project starts it in a doriath session of PROFILE for this
# project. Several profiles compose, each over the ones before it. repo:NAME
# names the profile .doriath/NAME.toml of the repository.
# Without --command, NAME is the command of the agent whose module
# the profile lists, such as claude. The shim lives outside the project,
# where no agent writes.
use_doriath() {
  local profile= command=
  while [ $# -gt 0 ]; do
    case $1 in
      --command) command=${2:?use doriath: --command needs a name}; shift 2 ;;
      -*) log_error "use doriath: unknown argument $1"; return 1 ;;
      *) profile=${profile:+$profile+}$1; shift ;;
    esac
  done
  [ -n "$profile" ] || { log_error "use doriath: name the profile"; return 1; }
  local doriath
  doriath=$(command -v doriath) || { log_error "use doriath: doriath is not on PATH"; return 1; }
  if [ -z "$command" ]; then
    command=$("$doriath" __agent-command "$profile") || { log_error "use doriath: name the agent's command with --command"; return 1; }
  fi
  local root=$PWD
  local dir
  dir="${XDG_CACHE_HOME:-$HOME/.cache}/doriath/shims/$(printf '%s' "$root" | sha256sum | cut -c1-16)"
  mkdir -p "$dir" || return 1
  {
    printf '#!%s\n' "$BASH"
    printf '# Written by doriath'\''s direnv library for %q.\n' "$root"
    printf 'PATH=$(printf %%s "$PATH" | tr : "\\n" | grep -vxF %q | paste -sd: -)\n' "$dir"
    printf 'export PATH\n'
    printf 'exec %q run --profile %q --current %q -- %q "$@"\n' "$doriath" "$profile" "$root" "$command"
  } >"$dir/$command.tmp" && chmod 755 "$dir/$command.tmp" && mv "$dir/$command.tmp" "$dir/$command" || return 1
  PATH_add "$dir"
}
