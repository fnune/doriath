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
      match = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "~/Development/project" ];
        description = "Directories where girdle run picks this profile without --profile.";
      };
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

  withoutNull = lib.filterAttrs (_: v: v != null);

  configFile = toml.generate "girdle-config.toml" (
    withoutNull {
      approvals = withoutNull { desktop = cfg.approvals.desktop; };
      secrets = lib.mapAttrs (_: withoutNull) cfg.secrets;
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

    approvals.desktop = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Show approval requests as desktop notifications with buttons.";
    };

    secrets = lib.mkOption {
      type = lib.types.attrsOf secretType;
      default = { };
      description = ''
        Where each named secret comes from. Profiles name secrets, never their
        values, so this file holds no secret material itself.
      '';
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
    assertions = lib.mapAttrsToList (name: s: {
      assertion = (s.file == null) != (s.command == null);
      message = "programs.girdle.secrets.${name}: set exactly one of file or command.";
    }) cfg.secrets;

    home.packages = [ cfg.package ];

    xdg.configFile =
      {
        "girdle/config.toml".source = configFile;
      }
      // lib.mapAttrs' (
        name: profile:
        lib.nameValuePair "girdle/profiles/${name}.toml" {
          source = toml.generate "girdle-profile-${name}.toml" (emptyLists profile);
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
