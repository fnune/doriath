{
  self,
  pkgs,
  home-manager,
}:
let
  inherit (pkgs) lib;
  doriath = self.packages.${pkgs.stdenv.hostPlatform.system}.default;

  homeWith =
    doriathConfig:
    home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        self.homeManagerModules.default
        {
          home = {
            username = "check";
            homeDirectory = "/home/check";
            stateVersion = "25.05";
          };
          programs.zsh.enable = true;
          programs.doriath = doriathConfig;
        }
      ];
    };

  home = homeWith {
    enable = true;
    approvals.desktop = false;
    approvals.web.enable = true;
    direnv = true;
    skill.enable = true;
    modules.team = {
      egress.allow = [ "team.example" ];
    };
    profiles.work = {
      description = "Work on the app";
      modules = [ "team" ];
      mounts = [
        {
          path = "~/Documents/notes";
          mode = "read";
        }
        {
          path = "~/Development/app";
          mode = "write";
        }
      ];
      secrets = {
        github.command = [
          "rbw"
          "get"
          "github"
        ];
        signing.file = "/run/secrets/signing";
      };
      packages = [ pkgs.hello ];
      egress = {
        allow = [ "api.github.com" ];
        programs = [
          {
            allow = [ "proxy.golang.org" ];
            binaries = [ "go" ];
          }
        ];
      };
    };
  };

  conflictingSecret = homeWith {
    enable = true;
    profiles.broken.secrets.both = {
      file = "/run/secrets/both";
      command = [ "true" ];
    };
  };
  # home-manager throws on failed assertions instead of exposing them, so the
  # valid home above is the control that the throw comes from the secret.
  conflictingSecretFails = !(builtins.tryEval conflictingSecret.activationPackage.drvPath).success;
in
assert lib.assertMsg conflictingSecretFails
  "a secret with both file and command must fail the module's assertion";
pkgs.runCommand "doriath-home-manager-module"
  {
    nativeBuildInputs = [
      doriath
      pkgs.jq
      pkgs.gnugrep
    ];
    homeFiles = home.config.home-files;
    hello = "${lib.getBin pkgs.hello}/bin";
  }
  ''
    config=$homeFiles/.config/doriath
    export HOME=$TMPDIR/home XDG_RUNTIME_DIR=$TMPDIR/run DORIATH_CONFIG_DIR=$config
    mkdir -p $HOME $XDG_RUNTIME_DIR

    doriath profiles show work --json > profile.json
    expect() {
      jq -e "$@" profile.json > /dev/null || { echo "profile work: expected $*"; cat profile.json; exit 1; }
    }
    expect --arg hello "$hello" '.Env.PathPrepend | index($hello) != null'
    expect '[.Mounts[] | select(.Mode == "write")] | length == 1'
    expect '.Secrets.github.Command == ["rbw", "get", "github"]'
    expect '.Secrets.signing.File == "/run/secrets/signing"'

    tables=$(grep '^\[' $config/config.toml)
    [ "$tables" = "[approvals]" ] || { echo "config.toml has more than [approvals]:"; cat $config/config.toml; exit 1; }
    grep -qx 'desktop = false' $config/config.toml || { cat $config/config.toml; exit 1; }
    ! grep -q '^packages' $config/profiles/work.toml || { echo "packages is not a profile key"; exit 1; }

    ! grep -q '^match' $config/profiles/work.toml || { echo "match is not a profile key"; exit 1; }
    grep -q 'use_doriath()' $config/../direnv/lib/doriath.sh || { echo "no direnv library"; exit 1; }
    for dir in .claude/skills .agents/skills; do
      grep -q 'doriath guide profile' $homeFiles/$dir/setting-up-doriath-profiles/SKILL.md || { echo "no skill in $dir"; exit 1; }
    done
    grep -q 'completion zsh' $homeFiles/.zshrc || { echo "no completion in .zshrc"; exit 1; }
    grep -q ' web --listen 127.0.0.1:7341' $homeFiles/.config/systemd/user/doriath-web.service || { echo "no approvals page service"; exit 1; }

    touch $out
  ''
