package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

const zshCompletion = `#compdef doriath
# Load with: source <(doriath completion zsh), or save as _doriath in $fpath.

_doriath() {
  local -a commands
  commands=(
    'run:run a command in a jail'
    'approvals:list and decide pending requests'
    'web:serve the approvals page, or open it'
    'exec:run a command in a running jail'
    'forward:reach a port of a running jail'
    'status:list sessions, or show what one allows'
    'log:show the audit log'
    'profiles:list, show, edit, allow, sign in to or clean profiles'
    'modules:list or show modules'
    'clean:remove merged agent worktrees and old branch backups'
    'restore:put back the branches a session moved'
    'direnv:print the direnv library'
    'doctor:check this machine'
    'completion:print a shell completion script'
    'version:print the version'
  )
  if (( CURRENT == 2 )); then
    _describe 'doriath command' commands
    return
  fi
  case "${words[2]}" in
    run)
      _arguments '--profile[profile to use]:profile:($(doriath __complete profiles))' '*::command:_normal' ;;
    approvals)
      if (( CURRENT == 3 )); then
        _values 'subcommand' list allow deny grant
      elif [[ "${words[3]}" == (allow|deny) ]] && (( CURRENT == 4 )); then
        _values 'request' $(doriath __complete approvals)
      elif [[ "${words[3]}" == allow ]]; then
        _arguments '--for[how long the allow lasts]:lasting:(once session 15m 1h)'
      elif [[ "${words[3]}" == grant ]]; then
        _arguments '--session[the session]:session:($(doriath __complete sessions))' '*:path:_files'
      fi ;;
    web)
      if (( CURRENT == 3 )); then
        _values 'subcommand' open
      fi ;;
    profiles)
      if (( CURRENT == 3 )); then
        _values 'subcommand' list show edit allow login clean
      else
        _values 'profile' $(doriath __complete profiles)
      fi ;;
    modules)
      if (( CURRENT == 3 )); then
        _values 'subcommand' list show
      else
        _values 'module' $(doriath __complete modules)
      fi ;;
    status|exec|forward)
      _arguments '--session[the session]:session:($(doriath __complete sessions))' ;;
    restore)
      if (( CURRENT == 3 )); then
        _values 'session' $(doriath __complete records)
      fi ;;
    log)
      _arguments '--session[only this session]:session:($(doriath __complete sessions))' \
        '--profile[only this profile]:profile:($(doriath __complete profiles))' \
        '--denied[only denials]' '--since[only the last duration]:duration:' '--json[JSON lines]' '--follow[keep printing]' ;;
    completion)
      _values 'shell' zsh ;;
  esac
}

compdef _doriath doriath
`

func cmdCompletion(args []string, w io.Writer) error {
	if len(args) != 1 || args[0] != "zsh" {
		return errors.New("completion: usage: doriath completion zsh")
	}
	_, err := io.WriteString(w, zshCompletion)
	return err
}

func cmdComplete(args []string, w io.Writer) {
	if len(args) != 1 {
		return
	}
	p, err := paths()
	if err != nil {
		return
	}
	switch args[0] {
	case "profiles":
		names, _ := loader(p, "").Names()
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
	case "modules":
		names, _ := moduleNames(p)
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
	case "sessions":
		sessions, _ := liveSessions(p)
		for _, s := range sessions {
			fmt.Fprintln(w, s.info.ID)
		}
	case "records":
		recs, _ := records(p)
		for _, rec := range recs {
			fmt.Fprintln(w, rec.Session)
		}
	case "approvals":
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		reqs, _ := pending(ctx, p)
		for _, r := range reqs {
			fmt.Fprintln(w, r.ID)
		}
	}
}
