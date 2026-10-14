self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.girdle;
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
        description = "One line that girdle profiles list shows.";
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

  configFile = toml.generate "girdle-config.toml" (
    withoutNull {
      approvals = withoutNull { desktop = cfg.approvals.desktop; };
    }
  );

  emptyLists = lib.filterAttrs (_: v: v != [ ] && v != "");
in
{
  options.programs.girdle = {
    enable = lib.mkEnableOption "Girdle of Melian, a jail for coding agents";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "girdle.packages.\${system}.default";
      description = "Which build of girdle to install.";
    };

    zsh = {
      completion = lib.mkOption {
        type = lib.types.bool;
        default = config.programs.zsh.enable;
        defaultText = lib.literalExpression "config.programs.zsh.enable";
        description = "Load girdle's zsh completion.";
      };
    };

    approvals.desktop = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Show approval requests as desktop notifications with buttons.";
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
          message = "programs.girdle.profiles.${profile}.secrets.${name}: set exactly one of file or command.";
        }) p.secrets
      ) cfg.profiles
    );

    home.packages = [ cfg.package ];

    programs.zsh.initContent = lib.mkIf cfg.zsh.completion ''
      source <(${lib.getExe cfg.package} completion zsh)
    '';

    xdg.configFile =
      {
        "girdle/config.toml".source = configFile;
      }
      // lib.mapAttrs' (
        name: profile:
        lib.nameValuePair "girdle/profiles/${name}.toml" {
          source = toml.generate "girdle-profile-${name}.toml" (emptyLists (profileToml profile));
        }
      ) cfg.profiles
      // lib.mapAttrs' (
        name: module:
        lib.nameValuePair "girdle/modules/${name}.toml" {
          source = toml.generate "girdle-module-${name}.toml" (emptyLists module);
        }
      ) cfg.modules;
  };
}
