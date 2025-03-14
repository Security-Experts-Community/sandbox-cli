{
  description = "Command line tool for interaction with sandboxes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    pyproject-nix.url = "github:nix-community/pyproject.nix";
    flake-utils.url = "github:numtide/flake-utils";
    ptsandbox.url = "github:Security-Experts-Community/py-ptsandbox";
  };

  outputs = {
    nixpkgs,
    pyproject-nix,
    flake-utils,
    ptsandbox,
    ...
  }: let
    outputs = flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      python = pkgs.python3.override {
        packageOverrides = self: super: {
          ptsandbox-pt27b15e = ptsandbox.packages.${system}.py-ptsandbox;
        };
      };

      project = pyproject-nix.lib.project.loadUVPyproject {
        projectRoot = ./.;
      };
    in rec {
      packages = {
        sandbox-cli = let
          attrs = project.renderers.buildPythonPackage {inherit python;};
        in
          python.pkgs.buildPythonApplication attrs
          // {};
      };

      defaultPackage = packages.sandbox-cli;

      homeManagerModules.sandbox-cli = {
        imports = [./modules];
      };
    });
  in
    outputs
    // {
      homeManagerModules.default = {
        imports = [./modules];
      };

      overlays.default = final: prev: {
        sandbox-cli = outputs.packages.${prev.system}.sandbox-cli;
      };
    };
}
