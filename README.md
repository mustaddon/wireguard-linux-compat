# WireGuard for Linux 3.10 - 5.5

WireGuard was merged into the Linux kernel for 5.6. This repository contains a backport of WireGuard for kernels 3.10 to 5.5, as an out of tree module.

**More information may be found at [WireGuard.com](https://www.wireguard.com/).**

## License

This project is released under the [GPLv2](COPYING).


```bash
wget --no-cache -O wgp-install.sh https://raw.githubusercontent.com/mustaddon/wireguard-linux-compat/refs/heads/test4/kernel-tree-scripts/install.sh
sudo bash wgp-install.sh
```

```bash
wget --no-cache -O wg-server.sh https://raw.githubusercontent.com/mustaddon/wireguard-linux-compat/refs/heads/test4/kernel-tree-scripts/server.sh
sudo bash wg-server.sh
```