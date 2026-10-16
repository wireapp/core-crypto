{
  description = "Development shell for Wire CoreCrypto";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rustup
              cargo-nextest
              gnumake
              fd
              git
              jq
              pkg-config
              cmake
              perl
              clang
              binaryen
            ];

            shellHook = ''
              echo "CoreCrypto development shell (Rust toolchain from rust-toolchain.toml)"
            '';
          };
        });
    };
}
