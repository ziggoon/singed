# install rustup & cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# install rust toolchains for aarch64, x86, and x64
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-gnu
rustup target add i686-unknown-linux-gnu

# install gcc / cross-compilation pkgs
apt-get -y install gcc-x86-64-linux-gnu gcc-i686-linux-gnu gcc-aarch64-linux-gnu libssl-dev pkg-config
