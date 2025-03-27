{
  description = "Command line tool for interaction with sandboxes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    pyproject-nix = {
      url = "github:nix-community/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    ptsandbox = {
      url = "github:Security-Experts-Community/py-ptsandbox";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    self,
    nixpkgs,
    pyproject-nix,
    flake-utils,
    ptsandbox,
    ...
  }: let
    outputs = flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};

        python = pkgs.python3.override {
          packageOverrides = self: super: {
            ptsandbox = ptsandbox.packages.${system}.py-ptsandbox;
          };
        };

        project = pyproject-nix.lib.project.loadUVPyproject {
          projectRoot = ./.;
        };

        projectAttrsForApp = project.renderers.buildPythonPackage {inherit python;};
        projectAttrsForEnv = project.renderers.withPackages {inherit python;};
        projectEnv = python.withPackages projectAttrsForEnv;
      in {
        packages = {
          sandbox-cli = python.pkgs.buildPythonApplication (projectAttrsForApp // {});
          default = self.packages.${system}.sandbox-cli;
        };

        devShells.default = pkgs.mkShell {
          packages = [
            projectEnv
          ];

          shellHook = ''
            unlink .nix-venv; ln -s ${projectEnv} ./.nix-venv
          '';
        };
      }
    );
  in
    outputs
    // {
      homeManagerModules = {
        sandbox-cli = import ./modules self;
        default = self.homeManagerModules.sandbox-cli;
      };

      overlays.default = final: prev: {
        sandbox-cli = self.packages.${prev.system}.sandbox-cli;
      };
    };
}
