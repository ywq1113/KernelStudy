# Build

## Download

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.10.14.tar.xz
tar -xJvf linux-6.10.14.tar.xz
```

## Build

### x86 env

```bash
sudo ./bootstrap.sh
cd linux-6.10.14/
scripts/config --enable IKCONFIG --enable IKCONFIG_PROC
make x86_64_defconfig
make -j"$(nproc)" bindeb-pkg LOCALVERSION=-custom
```

### Arm env

```bash
sudo apt install -y \
  clang clangd llvm llvm-dev llvm-runtime \
  lld \
  flex bison \
  libelf-dev libssl-dev libncurses-dev \
  build-essential

export ARCH=arm64
export LLVM=1
export CC=clang

# clean 
make mrproper

# config && make
make defconfig
make compile_commands.json
```
