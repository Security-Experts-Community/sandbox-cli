flake: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.programs.sandbox-cli;

  # copypasted from library function, except one part
  filterAttrsRecursive = pred: set: let
    filterInner = v: (
      if lib.isAttrs v
      then filterAttrsRecursive pred v
      else
        # in library version here just `v` returns
        # but here we need to recursively crawl through lists
        (
          if lib.isList v
          then (lib.map filterInner v)
          else v
        )
    );
  in
    lib.listToAttrs (
      lib.concatMap (
        name: let
          v = set.${name};
        in
          if pred name v
          then [(lib.nameValuePair name (filterInner v))]
          else []
      ) (lib.attrNames set)
    );

  recursiveRemoveNull = attrs: filterAttrsRecursive (n: v: v != null) attrs;

  tomlFormat = pkgs.formats.toml {};

  # need to remove nulls from settings before passing to toml generator, because toml generator
  # screams about nulls and don't want to work properly.
  tomledSettings = tomlFormat.generate "sandbox-config" (recursiveRemoveNull cfg.settings);

  nullOrSubmodule = submod: lib.types.nullOr (lib.types.submodule submod);
  listOfSubmodule = submod: lib.types.listOf (lib.types.submodule submod);
in {
  options.programs.sandbox-cli = with lib; {
    enable = mkEnableOption "sandbox-cli";

    package = mkOption {
      type = types.package;
      default = flake.packages.${pkgs.system}.sandbox-cli;
      description = "The package to use for sandbox-cli";
    };

    settings = mkOption {
      type = types.submodule {
        options = {
          passwords = mkOption {
            type = types.nullOr (types.listOf types.str);
            default = null;
          };

          browser = mkOption {
            type = nullOrSubmodule {
              options = {
                path = mkOption {
                  type = types.str;
                };

                args = mkOption {
                  type = types.str;
                };
              };
            };

            default = null;
          };

          rules-path = mkOption {
            type = types.nullOr (types.str);
            default = null;
          };

          docker = mkOption {
            type = nullOrSubmodule {
              options = {
                username = mkOption {
                  type = types.str;
                };

                token = mkOption {
                  type = types.str;
                };

                registry = mkOption {
                  type = types.str;
                };

                image-name = mkOption {
                  type = types.str;
                };

                image-tag = mkOption {
                  type = types.str;
                };
              };
            };

            default = null;
          };

          sandbox = mkOption {
            type = listOfSubmodule {
              options = {
                name = mkOption {
                  type = types.str;
                };

                key = mkOption {
                  type = types.str;
                };

                host = mkOption {
                  type = types.str;
                };

                max-workers = mkOption {
                  type = types.nullOr types.int;
                  default = null;
                };

                description = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                };

                ssh = mkOption {
                  type = nullOrSubmodule {
                    options = {
                      username = mkOption {
                        type = types.str;
                      };

                      password = mkOption {
                        type = types.str;
                      };
                    };
                  };

                  default = null;
                };
              };
            };

            default = [];
          };
        };
      };

      default = {};

      example = lib.literalExpression ''
        {
          passwords = [
            "infected"
            "password"
          ];

          docker = {
            username = "";
            token = "";
            registry = "";
            image-name = "";
            image-tag = "";
          };

          sandbox = [
            {
              name = "key-1";
              key = "";
              host = "";
              max-workers = 8;
              ssh = {
                username = "";
                password = "";
              };
            }
            {
              name = "key-1";
              key = "";
              host = "";
              max-workers = 8;
            }
          ];
        }
      '';

      description = ''
        Configuration written to
        {file}`$XDG_CONFIG_HOME/sandbox-cli/config.toml`.

        See <https://github.com/Security-Experts-Community/sandbox-cli> for full documentation
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [cfg.package];

    xdg.configFile."sandbox-cli/config.toml" = lib.mkIf (cfg.settings != {}) {
      source = tomledSettings;
    };
  };
}
