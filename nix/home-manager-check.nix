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
    approvals.host_wait = "30s";
    approvals.tool_wait = "90s";
    approvals.web.enable = true;
    terminal.title = false;
    terminal.bar = false;
    direnv = true;
    skill.enable = true;
    modules.team = {
      egress.allow = [ "team.example" ];
      uses_secrets = [ "api" ];
      http = [
        {
          host = "api.team.example";
          credential = {
            secret = "api";
            scheme = "bearer";
          };
          default = "deny";
          rules = [
            {
              method = "GET";
              path = "/items";
              action = "allow";
            }
          ];
        }
      ];
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
        github = {
          command = [
            "rbw"
            "get"
            "github"
          ];
          required = true;
          refresh = "45m";
        };
        signing.file = "/run/secrets/signing";
        api.oauth.mcp = "https://mcp.team.example/mcp";
        issuer.oauth = {
          issuer = "https://login.team.example";
          client_id = "doriath";
          scopes = [
            "read"
            "write"
          ];
        };
      };
      packages = [ pkgs.hello ];
      env.path_prepend = [ "/opt/team/bin" ];
      hardening.namespaces = false;
      limits.tasks = 256;
      mcp = [
        {
          name = "team";
          url = "https://api.team.example/mcp";
          secret = "api";
          allow = [ "read_items" ];
        }
      ];
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

  userConfigs = {
    defaults = homeWith { enable = true; };
    headless = homeWith {
      enable = true;
      approvals.desktop = false;
    };
    configured = home;
    zero-wait = homeWith {
      enable = true;
      approvals.host_wait = "0s";
    };
  };

  configCheck = doriath.overrideAttrs {
    pname = "doriath-home-manager-config";
    DORIATH_HOME_MANAGER_PROFILE = home.config.xdg.configFile."doriath/profiles/work.toml".source;
    DORIATH_HOME_MANAGER_FIXTURES = pkgs.linkFarm "doriath-user-configs" (
      lib.mapAttrsToList (name: home: {
        name = "${name}.toml";
        path = home.config.xdg.configFile."doriath/config.toml".source;
      }) userConfigs
    );
    preBuild = "";
    buildPhase = ''
      runHook preBuild
      go test ./internal/config ./internal/profile -run '^TestHomeManager(Config|Secrets)$' -count=1
      runHook postBuild
    '';
    doCheck = false;
    installPhase = "touch $out";
  };

  invalidSecrets = [
    { }
    {
      file = "/run/secrets/both";
      command = [ "true" ];
    }
    {
      file = "/run/secrets/both";
      oauth.mcp = "https://mcp.team.example/mcp";
    }
    {
      command = [ "true" ];
      oauth.mcp = "https://mcp.team.example/mcp";
    }
    {
      file = "/run/secrets/all";
      command = [ "true" ];
      oauth.mcp = "https://mcp.team.example/mcp";
    }
  ];
  invalidSecretsFail = builtins.all (
    secret:
    let
      invalidHome = homeWith {
        enable = true;
        profiles.broken.secrets.invalid = secret;
      };
    in
    !(builtins.tryEval invalidHome.activationPackage.drvPath).success
  ) invalidSecrets;
in
assert builtins.isString home.activationPackage.drvPath;
assert lib.assertMsg invalidSecretsFail "a secret must have exactly one of file, command or oauth";
pkgs.runCommand "doriath-home-manager-module"
  {
    nativeBuildInputs = [
      doriath
      pkgs.jq
      pkgs.gnugrep
    ];
    homeFiles = home.config.home-files;
    inherit configCheck;
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
    expect --arg hello "$hello" '.Env.PathPrepend == [$hello, "/opt/team/bin"]'
    expect '[.Mounts[] | select(.Mode == "write")] | length == 1'
    expect '.Secrets.github.Command == ["rbw", "get", "github"]'
    expect '.Secrets.signing.File == "/run/secrets/signing"'
    expect '.Secrets.github.Refresh == 2700000000000'
    expect '.Secrets.api.OAuth.MCP == "https://mcp.team.example/mcp"'
    expect '.Secrets.issuer.OAuth | .Issuer == "https://login.team.example" and .ClientID == "doriath" and .Scopes == ["read", "write"]'
    expect '.HTTP[] | select(.Host == "api.team.example") | .Credential.Secret == "api" and .Rules[0].Path == "/items"'
    expect '.MCP[0] | .Name == "team" and .Secret == "api"'
    expect '[.HTTP[].Rules[] | select(.MCPTools == ["read_items"] and .Action == "allow")] | length == 1'
    expect '.Hardening.Namespaces == false and .Limits.Tasks == 256'
    grep -qx 'required = true' $config/profiles/work.toml || { echo "secrets.github.required is not in the profile"; cat $config/profiles/work.toml; exit 1; }

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
