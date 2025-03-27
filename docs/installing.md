# Install sandbox-cli

`sandbox-cli` is availabe as [sandbox-cli](https://pypi.org/project/sandbox-cli/) on PyPi.

Can be installed with `pipx` (recommeded) or `pip`:

```shell
# with pipx
pipx install sandbox-cli

# with pip
pip install sandbox-cli
```

Also available as `Nix` package with configuration customization:

First, add repo to flake inputs:

```nix title="flake.nix"
{
  inputs = {
    sandbox-cli = {
      url = "github:Security-Experts-Community/sandbox-cli";
    };
  };
}
```

Second, write the config for your home-manager configuration (`programs.sandbox-cli.settings` is 1-1 mapping of the [configuration](./configuration.md))

```nix title="module.nix"
{ inputs, lib, pkgs, ... }:
{
  imports = [
    inputs.sandbox-cli.homeManagerModules.default
  ];

  programs.sandbox-cli = {
    enable = true;

    settings = {
      sandbox = [
        {
          name = "sample-key-name";
          key = "sample-key";
          host = "127.0.0.1";
          max-workers = 1;
        }
      ];
    };
  };
}
```

Alternatively you can install the only `sandbox-cli` app to your environment and write config by hand:

```nix
{
    home.packages = [ inputs.sandbox-cli.packages.${pkgs.system}.sandbox-cli ];
}
```

Alternatively you can use overlay from `inputs.sandbox-cli.overlays.default`
