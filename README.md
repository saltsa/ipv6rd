# ipv6rd sciprt

Automatically configures IPv6 6rd tunneling in Linux hosts.

## Usage and installation

Building requires Go (tested with version 1.25).

To build:

```sh
go build
```

To install:

```sh
 cp ipv6rd /etc/NetworkManager/dispatcher.d
 chmod 755 /etc/NetworkManager/dispatcher.d/ipv6rd
```

After this everything should just work. Trigger DHCP renew by `systemctl restart NetworkManager`.
