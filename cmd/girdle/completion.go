package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

const zshCompletion = `#compdef girdle
# Load with: source <(girdle completion zsh), or save as _girdle in $fpath.

_girdle() {
  local -a commands
  commands=(
    'run:run a command in a jail'
    'approvals:list and decide pending requests'
    'sessions:list running sessions'
    'status:show what a session allows'
    'log:show the audit log'
    'profiles:list, show or edit profiles'
    'clean:remove merged agent worktrees and old branch backups'
    'restore:put back the branches a session moved'
    'grant:make a path writable in a running session'
    'doctor:check this machine'
    'completion:print a shell completion script'
    'version:print the version'
  )
  if (( CURRENT == 2 )); then
    _describe 'girdle command' commands
    return
  fi
  case "${words[2]}" in
    run)
      _arguments '--profile[profile to use]:profile:($(girdle __complete profiles))' '*::command:_normal' ;;
    approvals)
      if (( CURRENT == 3 )); then
        _values 'subcommand' list allow deny watch
      elif [[ "${words[3]}" == (allow|deny) ]] && (( CURRENT == 4 )); then
        _values 'request' $(girdle __complete approvals)
      elif [[ "${words[3]}" == allow ]]; then
        _arguments '--for[how long the allow lasts]:lasting:(once session 15m 1h)'
      fi ;;
    profiles)
      if (( CURRENT == 3 )); then
        _values 'subcommand' list show edit
      else
        _values 'profile' $(girdle __complete profiles)
      fi ;;
    clean)
      _arguments '--caches[remove the caches of a profile]:profile:($(girdle __complete profiles))' ;;
    status)
      _values 'session' $(girdle __complete sessions) ;;
    log)
      _arguments '--session[only this session]:session:($(girdle __complete sessions))' \
        '--profile[only this profile]:profile:($(girdle __complete profiles))' \
        '--denied[only denials]' '--since[only the last duration]:duration:' '--json[JSON lines]' '--follow[keep printing]' ;;
    completion)
      _values 'shell' zsh ;;
  esac
}

compdef _girdle girdle
`

func cmdCompletion(args []string, w io.Writer) error {
	if len(args) != 1 || args[0] != "zsh" {
		return errors.New("completion: usage: girdle completion zsh")
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
		names, _ := loader(p).Names()
		for _, n := range names {
			fmt.Fprintln(w, n)
		}
	case "sessions":
		sessions, _ := liveSessions(p)
		for _, s := range sessions {
			fmt.Fprintln(w, s.info.ID)
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
