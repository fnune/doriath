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
          "base"
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
    // lib.optionalAttrs (profile.secrets != { }) { secrets = lib.mapAttrs (_: withoutNull) profile.secrets; };

  withoutNull = lib.filterAttrs (_: v: v != null);

  configFile = toml.generate "doriath-config.toml" (
    lib.filterAttrs (_: v: v != { }) {
      approvals = withoutNull { desktop = cfg.approvals.desktop; };
      terminal = lib.optionalAttrs (!cfg.terminal.title) { title = false; };
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

    zsh = {
      completion = lib.mkOption {
        type = lib.types.bool;
        default = config.programs.zsh.enable;
        defaultText = lib.literalExpression "config.programs.zsh.enable";
        description = "Load doriath's zsh completion.";
      };
    };

    approvals.desktop = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Show approval requests as desktop notifications with buttons.";
    };

    terminal.title = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Name the session's profile in the terminal's window title while a session runs.";
    };

    approvals.web = {
      enable = lib.mkEnableOption "the approvals page as a systemd user service; `doriath web open` opens it";
      listen = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:7341";
        description = "The loopback HOST:PORT the page serves on.";
      };
    };

    modules = lib.mkOption {
      type = lib.types.attrsOf layerType;
      default = { };
      description = "Your own modules. A module with the name of a built-in one replaces it.";
    };

    profiles = lib.mkOption {
      type = lib.types.attrsOf profileType;
      default = { };
      description = "Profiles, one per kind of work or repository.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = lib.flatten (
      lib.mapAttrsToList (
        profile: p:
        lib.mapAttrsToList (name: s: {
          assertion = (s.file == null) != (s.command == null);
          message = "programs.doriath.profiles.${profile}.secrets.${name}: set exactly one of file or command.";
        }) p.secrets
      ) cfg.profiles
    );

    home.packages = [ cfg.package ];

    systemd.user.services.doriath-web = lib.mkIf cfg.approvals.web.enable {
      Unit.Description = "Doriath approvals page";
      Service = {
        ExecStart = "${lib.getExe cfg.package} web --listen ${cfg.approvals.web.listen}";
        Restart = "on-failure";
      };
      Install.WantedBy = [ "default.target" ];
    };

    programs.zsh.initContent = lib.mkIf cfg.zsh.completion ''
      source <(${lib.getExe cfg.package} completion zsh)
    '';

    xdg.configFile =
      lib.optionalAttrs cfg.direnv {
        "direnv/lib/doriath.sh".source = pkgs.runCommand "doriath-direnv.sh" { } "${lib.getExe cfg.package} direnv > $out";
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
