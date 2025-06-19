{
  description = "Tayga NAT64";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        versionSuffix = if self ? rev then "" else "-g${self.dirtyShortRev}";
        version = "0.9.4${versionSuffix}";
        pkgs = nixpkgs.legacyPackages.${system};
        iperf3 = pkgs.python3Packages.buildPythonPackage rec {
          pname = "iperf3";
          version = "0.1.11";
          src = pkgs.fetchPypi {
            inherit pname version;
            hash = "sha256-1Q7rvy3PRFoXP5ioL5xDPgMC09+3mH4fIbhrNe9jziY=";
          };
          propagatedBuildInputs = [pkgs.iperf3];
          postPatch = ''
            substituteInPlace iperf3/iperf3.py \
              --replace "lib_name = 'libiperf.so.0'" \
                        "lib_name = '${pkgs.iperf3}/lib/libiperf.so.0'"
          '';
        };
        tayga = pkgs.stdenv.mkDerivation (finalAttrs: {
          pname = "tayga";
          inherit version;
          src = ./.;
          configurePhase = ''
          mkdir .git
          touch .git/index
          cat > version.h << EOF
          #define TAYGA_VERSION "${finalAttrs.version}"
          #define TAYGA_BRANCH "main"
          #define TAYGA_COMMIT "${self.rev or self.dirtyRev}"
          EOF
          '';
          buildPhase = ''
            make tayga
          '';
          installPhase = ''
            make install PREFIX=$out
          '';
        });
      in {
        packages = {
          default = tayga;
          inherit tayga;
        };
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.linuxPackages_latest.perf
            pkgs.perf-tools
            pkgs.iperf
            pkgs.iproute2
            pkgs.kdePackages.kcachegrind
            pkgs.valgrind
            (pkgs.python3.withPackages (ps: [
              ps.scapy
              ps.pyroute2
              iperf3
            ]))
          ];
        };
        formatter = pkgs.alejandra;
      }
    );
}
