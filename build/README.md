# Build

**Download**

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.10.14.tar.xz
tar -xJvf linux-6.10.14.tar.xz
```

**Build**

```bash
sudo ./bootstrap.sh
cd linux-6.10.14/
scripts/config --enable IKCONFIG --enable IKCONFIG_PROC
make x86_64_defconfig
make -j"$(nproc)" bindeb-pkg LOCALVERSION=-custom
```

