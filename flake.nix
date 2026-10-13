{
  description = "Girdle of Melian: run coding agents in a jail that shows them only what their task needs";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = "0.1.0";

      girdleFor =
        pkgs:
        pkgs.buildGoModule {
          pname = "girdle";
          inherit version;
          src = nixpkgs.lib.cleanSource ./.;
          vendorHash = nixpkgs.lib.fileContents ./nix/vendor-hash;
          subPackages = [ "cmd/girdle" ];
          env.CGO_ENABLED = 0;
          tags = [ "bundled" ];
          ldflags = [
            "-s"
            "-w"
            "-X main.version=${version}"
          ];
          # The binary carries a static bubblewrap, so that it runs the same on
          # any distribution and does not depend on the system's copy.
          preBuild = ''
            mkdir -p internal/bundle/assets
            install -m 0644 ${pkgs.pkgsStatic.bubblewrap}/bin/bwrap internal/bundle/assets/bwrap
          '';
          # Unit tests only. The integration tests need user namespaces, which
          # the build sandbox does not offer.
          checkFlags = [ "-short" ];
          meta = {
            description = "Run coding agents in a jail that shows them only what their task needs";
            homepage = "https://github.com/fnune/girdle";
            license = nixpkgs.lib.licenses.mit;
            mainProgram = "girdle";
            platforms = nixpkgs.lib.platforms.linux;
          };
        };
    in
    {
      packages = forAllSystems (pkgs: rec {
        girdle = girdleFor pkgs;
        default = girdle;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.gofumpt
            pkgs.golangci-lint
            pkgs.govulncheck
            pkgs.just
            pkgs.prettier
          ];
          GIRDLE_STATIC_BWRAP = "${pkgs.pkgsStatic.bubblewrap}/bin/bwrap";
        };
      });

      checks = forAllSystems (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      });

      homeManagerModules.default = import ./nix/home-manager.nix self;
    };
}
