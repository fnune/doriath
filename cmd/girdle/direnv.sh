# girdle's direnv library. In .envrc at a project's root:
#
#   use girdle PROFILE [--command NAME]
#
# puts a shim for NAME (default claude) first on PATH, so that running it
# anywhere in the project starts it in a girdle session of PROFILE for this
# project. The shim lives outside the project, where no agent writes.
use_girdle() {
  local profile=${1:?use girdle: name the profile}
  shift
  local command=claude
  while [ $# -gt 0 ]; do
    case $1 in
      --command) command=${2:?use girdle: --command needs a name}; shift 2 ;;
      *) log_error "use girdle: unknown argument $1"; return 1 ;;
    esac
  done
  local girdle
  girdle=$(command -v girdle) || { log_error "use girdle: girdle is not on PATH"; return 1; }
  local root=$PWD
  local dir
  dir="${XDG_CACHE_HOME:-$HOME/.cache}/girdle/shims/$(printf '%s' "$root" | sha256sum | cut -c1-16)"
  mkdir -p "$dir" || return 1
  {
    printf '#!%s\n' "$BASH"
    printf '# Written by girdle'\''s direnv library for %q.\n' "$root"
    printf 'PATH=$(printf %%s "$PATH" | tr : "\\n" | grep -vxF %q | paste -sd: -)\n' "$dir"
    printf 'export PATH\n'
    printf 'exec %q run --profile %q --current %q -- %q "$@"\n' "$girdle" "$profile" "$root" "$command"
  } >"$dir/$command.tmp" && chmod 755 "$dir/$command.tmp" && mv "$dir/$command.tmp" "$dir/$command" || return 1
  PATH_add "$dir"
}
