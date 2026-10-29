self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.doriath;
  toml = pkgs.formats.toml { };

  layerType = lib.types.submodule {
    freeformType = toml.type;
    options.modules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Modules this layer builds on, applied in order before the layer itself.";
    };
  };

  secretType = lib.types.submodule {
    options = {
      file = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "A file that holds the secret. It must not be readable by other users.";
      };
      command = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        example = [
          "rbw"
          "get"
          "github-project"
        ];
        description = "A command whose standard output is the secret, such as sops, rbw, op or secret-tool.";
      };
      oauth = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.submodule {
            options = {
              mcp = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "The HTTPS URL of an MCP server that supplies its OAuth login details.";
              };
              issuer = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "The HTTPS URL of the OAuth issuer, when mcp is not set.";
              };
              client_id = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "The client ID for an explicit issuer. An MCP server registers its own client.";
              };
              scopes = lib.mkOption {
                type = lib.types.nullOr (lib.types.listOf lib.types.str);
                default = null;
                description = "The scopes to request during the OAuth login.";
              };
            };
          }
        );
        default = null;
        example = {
          mcp = "https://mcp.example.com/mcp";
        };
        description = "An OAuth login. Set mcp, or set issuer and client_id. Complete the login with `doriath profiles login NAME`.";
      };
      refresh = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "45m";
        description = "Read a file or command secret again after this duration, at least 1m. OAuth logins refresh automatically.";
      };
      required = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        description = "Stop the session when the secret fails. Without it, the session starts and what needs the secret fails.";
      };
    };
  };

  profileType = lib.types.submodule {
    freeformType = toml.type;
    options = {
      description = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "One line that doriath profiles list shows.";
      };
      modules = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "vcs-readwrite"
          "nix"
          "go"
          "github"
          "claude"
        ];
        description = "Built-in or user modules this profile builds on.";
      };
      secrets = lib.mkOption {
        type = lib.types.attrsOf secretType;
        default = { };
        example = lib.literalExpression ''{ github.command = [ "rbw" "get" "github-my-app" ]; }'';
        description = ''
          Where each secret this profile uses comes from. Only this profile
          sees them; to use a secret in another profile, name it there too.
        '';
      };
      packages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [ ];
        example = lib.literalExpression "[ pkgs.xvfb-run ]";
        description = ''
          Tools for the jail that the host does not install. Their bin
          directories go in front of the jail's PATH, through env.path_prepend.
        '';
      };
    };
  };

  # packages is not a profile key: it becomes env.path_prepend.
  profileToml =
    profile:
    let
      bins = map (p: "${lib.getBin p}/bin") profile.packages;
      env = profile.env or { };
      withPath =
        if bins == [ ] then
          { }
        else
          {
            env = env // {
              path_prepend = bins ++ (env.path_prepend or [ ]);
            };
          };
    in
    builtins.removeAttrs profile [
      "packages"
      "secrets"
    ]
    // withPath
    // lib.optionalAttrs (profile.secrets != { }) {
      secrets = lib.mapAttrs (
        _: secret: lib.filterAttrsRecursive (_: value: value != null) secret
      ) profile.secrets;
    };

  withoutNull = lib.filterAttrs (_: v: v != null);

  configFile = toml.generate "doriath-config.toml" (
    lib.filterAttrs (_: v: v != { }) {
      approvals = withoutNull {
        inherit (cfg.approvals) host_wait tool_wait;
      };
      desktop = {
        inherit (cfg.desktop) notifications tray;
      };
      terminal =
        lib.optionalAttrs (!cfg.terminal.title) { title = false; }
        // lib.optionalAttrs (!cfg.terminal.bar) { bar = false; }
        // lib.optionalAttrs (cfg.terminal.env != { }) { inherit (cfg.terminal) env; };
    }
  );

  emptyLists = lib.filterAttrs (_: v: v != [ ] && v != "");
in
{
  options.programs.doriath = {
    enable = lib.mkEnableOption "Doriath, a jail for coding agents";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "doriath.packages.\${system}.default";
      description = "Which build of doriath to install.";
    };

    direnv = lib.mkOption {
      type = lib.types.bool;
      default = config.programs.direnv.enable;
      defaultText = lib.literalExpression "config.programs.direnv.enable";
      description = ''
        Install doriath's direnv library, so that `use doriath PROFILE` in a
        project's .envrc starts its agent command in a doriath session.
      '';
    };

    skill = {
      enable = lib.mkEnableOption "a skill that tells an agent to run `doriath guide profile` and follow it";
      directories = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          ".claude/skills"
          ".agents/skills"
        ];
        description = ''
          Folders under the home directory where agents read skills. Codex,
          Gemini CLI and opencode read .agents/skills.
        '';
      };
    };

    zsh = {
      completion = lib.mkOption {
        type = lib.types.bool;
        default = config.programs.zsh.enable;
        defaultText = lib.literalExpression "config.programs.zsh.enable";
        description = "Load doriath's zsh completion.";
      };
    };

    desktop = {
      notifications = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Show approval requests as desktop notifications with buttons.";
      };
      web = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Run the approvals page as a systemd user service; `doriath web open` opens it.";
        };
        listen = lib.mkOption {
          type = lib.types.str;
          default = "127.0.0.1:7341";
          description = "The loopback HOST:PORT the page serves on.";
        };
      };
      tray = lib.mkOption {
        type = lib.types.bool;
        default = cfg.desktop.web.enable;
        defaultText = lib.literalExpression "config.programs.doriath.desktop.web.enable";
        description = ''
          Show an icon in the desktop's status area while the approvals page
          runs. It marks requests that wait for an answer, and a click opens
          the page. The service then starts with the graphical session.
        '';
      };
    };

    approvals.host_wait = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "30s";
      description = "How long a refused request waits for approval, from 0s to 1h. Null uses 2m with desktop notifications, otherwise 0s.";
    };

    approvals.tool_wait = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "90s";
      description = "How long an agent permission prompt waits for approval. Use a positive duration up to 1h. Null uses 60s.";
    };

    terminal.title = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Name the session's profile in the terminal's window title while a session runs.";
    };

    terminal.bar = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Show the session on the terminal's last row, below the agent.";
    };

    terminal.env = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        HERDR_AGENT = "{command}";
      };
      description = "Variables for the process your terminal sees in place of the agent. {command} is the name of the command doriath runs. The jail does not get them.";
    };

    modules = lib.mkOption {
      type = lib.types.attrsOf layerType;
      default = { };
      description = "Your own modules. A module with the name of a built-in one is an error.";
    };

    profiles = lib.mkOption {
      type = lib.types.attrsOf profileType;
      default = { };
      description = "Profiles, one per kind of work or repository.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.desktop.tray -> cfg.desktop.web.enable;
        message = "programs.doriath.desktop.tray needs desktop.web.enable: a click on the icon opens the approvals page.";
      }
    ]
    ++ lib.flatten (
      lib.mapAttrsToList (
        profile: p:
        lib.mapAttrsToList (name: s: {
          assertion =
            lib.count (source: source != null) [
              s.file
              s.command
              s.oauth
            ] == 1;
          message = "programs.doriath.profiles.${profile}.secrets.${name}: set exactly one of file, command or oauth.";
        }) p.secrets
      ) cfg.profiles
    );

    home.packages = [ cfg.package ];

    systemd.user.services.doriath-web = lib.mkIf cfg.desktop.web.enable {
      Unit = {
        Description = "Doriath approvals page";
      }
      // lib.optionalAttrs cfg.desktop.tray {
        PartOf = [ "graphical-session.target" ];
        After = [ "graphical-session.target" ];
      };
      Service = {
        ExecStart = "${lib.getExe cfg.package} web --listen ${cfg.desktop.web.listen}";
        Restart = "on-failure";
      };
      Install.WantedBy = [ (if cfg.desktop.tray then "graphical-session.target" else "default.target") ];
    };

    home.file = lib.mkIf cfg.skill.enable (
      lib.listToAttrs (
        map (
          dir:
          lib.nameValuePair "${dir}/setting-up-doriath-profiles/SKILL.md" {
            source = pkgs.runCommand "doriath-skill.md" { } "${lib.getExe cfg.package} guide skill > $out";
          }
        ) cfg.skill.directories
      )
    );

    programs.zsh.initContent = lib.mkIf cfg.zsh.completion ''
      source <(${lib.getExe cfg.package} completion zsh)
    '';

    xdg.configFile =
      lib.optionalAttrs cfg.direnv {
        "direnv/lib/doriath.sh".source =
          pkgs.runCommand "doriath-direnv.sh" { }
            "${lib.getExe cfg.package} direnv > $out";
      }
      // {
        "doriath/config.toml".source = configFile;
      }
      // lib.mapAttrs' (
        name: profile:
        lib.nameValuePair "doriath/profiles/${name}.toml" {
          source = toml.generate "doriath-profile-${name}.toml" (emptyLists (profileToml profile));
        }
      ) cfg.profiles
      // lib.mapAttrs' (
        name: module:
        lib.nameValuePair "doriath/modules/${name}.toml" {
          source = toml.generate "doriath-module-${name}.toml" (emptyLists module);
        }
      ) cfg.modules;
  };
}
