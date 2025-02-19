# Build guide

The library compiles on the `1.51.0 stable` toolchain of the Rust compiler. To install Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the appropriate Rust toolchain by invoking:
```bash
rustup install 1.51.0
```
After that, use `cargo`, the standard Rust build tool, to build the library:
```bash
git clone https://github.com/HorizenOfficial/zendoo-mc-cryptolib.git
cd zendoo-mc-cryptolib
cargo build --release
```
This library comes with unit tests for each of the provided crates. Run the tests with:
```bash
cargo test --all-features 
```
Compiling with `adcxq`, `adoxq` and `mulxq` instructions can lead to a 30-70% speedup. These are available on most `x86_64` platforms (Broadwell onwards for Intel and Ryzen onwards for AMD). Run the following command:
```bash
RUSTFLAGS="-C target-feature=+bmi2,+adx" cargo test/build/bench --features asm
```
Tip: If optimising for performance, your mileage may vary with passing `--emit=asm` to `RUSTFLAGS`.
