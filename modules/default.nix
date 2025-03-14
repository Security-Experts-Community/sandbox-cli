{
  config,
  lib,
  pkgs,
  ...
}:
with lib; let
  cfg = config.programs.sandbox-cli;
  tomlFormat = pkgs.formats.toml {};
in {
  options.programs.sandbox-cli = {
    enable = mkEnableOption "sandbox-cli";

    package = mkOption {
      type = types.package;
      default = pkgs.sandbox-cli;
      description = "The package to use for sandbox-cli";
    };

    settings = mkOption {
      type = with types; let
        prim = oneOf [bool ints.unsigned str attrs];
        primOrPrimAttrs = either prim (attrsOf prim);
        entry = either prim (listOf primOrPrimAttrs);
        entryOrAttrsOf = t: either entry (attrsOf t);
        entries = entryOrAttrsOf (entryOrAttrsOf entry);
      in
        attrsOf entries // {description = "sandbox-cli configuration";};

      default = {};

      example = literalExpression ''
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

    xdg.configFile."sandbox-cli/config.toml" = mkIf (cfg.settings != {}) {
      source = tomlFormat.generate "sandbox-config" cfg.settings;
    };
  };
}
