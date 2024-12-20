# Bootstrapper

This repository contains a bootstrapper for network configuration.
It retrieves **hints** from available `zero conf` services to discover the IP address and port
of the **discovery server** serving the actual configuration files over HTTP.

It uses the following hinting mechanisms:
- DHCP option `www-server` and `Vendor-Identifying Vendor Option` [RFC2132],[RFC3925]
- DHCPv6 `Vendor-specific Information Option` [RFC3315]
- IPv6 NDP: DNS resolver and DNS Search List [RFC6106]
- DNS-SRV: DNS service resource records [RFC2782]
- DNS-NAPTR: Naming Authority Pointer DNS Resource Record [RFC2915]
- DNS-SD: DNS service discovery [RFC6763]
- mDNS: multicast DNS [RFC6762]

If the host being bootstrapped has no DNS search domain set, the rDNS functionality of DNS (as described in RFC1035)
is used to obtain a hostname and derive a search domain.
A query for the name `reversed-external-ip.in-addr-servers.arpa.` (or `reversed-external-ip.ip6.arpa` in the case of
IPv6) is sent to the default DNS resolver and resolved according to the delegation hierarchy.

---
**_NOTE:_**
In case there is no DNS search domain set on the host being bootstrapped **and**
that host has no public IP address, the *whoami* DNS service on `akamai.net` is used to resolve an
external IP.
As a further fallback, in case a nameserver for `akamai.net` cannot be resolved, the public DNS
resolver `9.9.9.9` provided by Quad9, headquartered in Switzerland and subject to Swiss privacy law, is used
to obtain the address of further nameservers.

The only information reaching those services are the external IP of the host and the information
that this host is using the *whoami* service to obtain that address.

All this is only a further fallback to provide zero-configuration bootstrapping even in misconfigured networks.

Calls to these two third-party services can be disabled entirely for a host by null routing their IP with the
`ip route add 9.9.9.9 via 127.0.0.1 dev lo` command and adding the entry `127.0.0.1   akamai.net` to the hosts file.
On the network level, calls to those fallbacks can be prevented by providing a proper DNS search domain configuration to
the endhost using DHCP(v6) or IPv6 RAs. In split-horizon DNS settings, the response to the nameserver query for
`akamai.net` can be shadowed if required to prevent the fallback.
Note that other services on your system might rely on those.

---

It integrates with SCION by using the same OpenAPI as the control service uses
for exposing TRCs (serving as root certificate) and the topology file
(describing the local SCION topology).

## Installing

Install from the netsec package repository at `https://packages.netsec.inf.ethz.ch/debian`:
`sudo apt-get install scion-bootstrapper`

## Building

To build the bootstrapper executable, simply run `make bootstrapper` in the top level directory.
In order to build the bootstrapper debian package, we use Bazel.
The service files are in the `./res/packaging/debian/` directory.
You can install Bazel by following the instructions at https://docs.bazel.build/versions/master/install-ubuntu.html
You can then build the package by running `make package_deb`.
When contributing, please run `make all` in order to make sure that all targets build and to run the linter.

Experimental availability is also provided for macOS and Windows. Run `make darwin` or `make windows` to build a
Mach-O or PE32+ binary respectively.

---
**NOTE**

On macOS, you might need to remove the IPv6 address(es) from your network interface if IPv6 connectivity is broken.
You can do so with the following command: `sudo networksetup -setv6off Ethernet`
 (use the flag `-setv6automatic` to reenable).\
On Windows, you might need to run the bootstrapper via the Command Prompt (cmd) instead of the PowerShell prompt.
Symlinking the output directory on shares or as unprivileged user is also not supported.
You can check your connection specific DNS suffix with `ipconfig` or
 in the advanced DNS settings of the adapter properties.

You might also need to explicitly allow the connections in your firewall, in particular for the broadcast based hinting
mechanisms.

---

## Running

The package starts the bootstrapper service at installation and adds a client hook to detect connectivity changes.\
It can be manually restarted with `sudo systemctl restart 'scion-bootstrapper@*.service'`

### Manual configuration
Generate a default configuration with `./scion-bootstrapper -help-config > ./bootstrapper.yml`.\
Run it with `./scion-bootstrapper -config bootstrapper.yml`.

## Client bootstrap service configuration

This file contains configuration options and provide some instructions to
get started.

## Discovery mechanisms

### DHCP (dnsmasq)

For example, with `dnsmasq`, an option 72 "Default WWW server" can be done by
adding the following line to `/etc/dnsmasq.conf`: `dhcp-option=72,<webserverIP>`.
Note that `dnsmasq` does not support DHCP option 72 `www-server` by default,
`https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html`, supported DHCP options are registered in `dhcp-common.c`.
`dhcpd` supports the option by default, `https://github.com/koenning/isc-dhcpd/blob/master/common/tables.c`.
Make sure to disable the options you don't need: By default `dnsmasq` is enabled to reply to DNS queries,
but it also has an integrated DHCP server that can be enabled for only specific interfaces or all interfaces.
Make sure to also check how `dnsmasq` interacts with the `resolvconf package` and your local network DHCP setup.

### DHCPv6 (dnsmasq)

DHCPv6 Option 17, Vendor-specific Information Option, is supported for discovery in IPv6 networks.
Note that the option code and length field width are different from DHCPv4.

### IPv6 NDP (dnsmasq)

IPv6 Neighbor Discovery Protocol Router Advertisements can be used to advertise DNS resolvers and DNS Search
Lists to be used in the DNS based discovery mechanisms.
Can be used in combination with DHCPv6, SLAAC or static address configuration.

### mDNS (avahi)

Put the following configuration to `/etc/avahi/services/sciondiscovery.service`:

```xml
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="no"></name>
  <service>
    <type>_sciondiscovery._tcp</type>
    <port>8041</port>
  </service>
</service-group>
```

Make sure to disable the features you don't need.

## Systemd service units

### Bootstrapper

A minimal example of the bootstrapper service units ``scion-bootstrapper@.service``.

```ini
[Unit]
After=network-online.target
Before=scion-daemon@%i.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/etc/scion/
ExecStartPre=/bin/mkdir -p /etc/scion/certs/
ExecStartPre=/bin/cp /etc/scion/boot.toml /etc/scion/boot-%i.toml
ExecStartPre=/bin/sed -i s#NIC#%i#g /etc/scion/boot-%i.toml
ExecStart=/opt/scion/bootstrapper -config boot-%i.toml
RemainAfterExit=True

# Raw network is needed for DHCP
AmbientCapabilities=CAP_NET_RAW
```

### SCIOND

A minimal example of the sciond service units ``scion-daemon-bootstrap@.service``.

```ini
[Unit]
After=network-online.target scion-bootstrapper@%i.service scion-dispatcher.service
BindsTo=scion-bootstrapper@%i.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/scion/
ExecStartPre=/bin/mkdir -p /etc/scion/gen-cache /var/cache/scion /run/shm/sciond
ExecStart=/opt/scion/sciond --config /etc/scion/sd.toml
```

## Nginx web server

After having installed Nginx, the network admin can follow these steps to
expose the endpoints needed by the bootstrapper:

- copy the site configuration to `/etc/nginx/sites-available` and enable it by creating
  a link that points to `/etc/nginx/sites-available/scion` in `/etc/nginx/sites-enabled`,
- create a link to the topology at `/srv/http/scion/topology.json`, and
- create a link to the *trc* index containing the TRCs to serve at
  `/srv/http/scion/trcs.json`.
- create a link to the *trc* metadata containing the description of a TRC at
  `/srv/http/scion/trcs/isd{isd}-b{base}-s{serial}.json`.
- create a link to the *trc* blob containing the TRC file itself at
  `/srv/http/scion/trcs/ISD{isd}-B{base}-S{serial}.trc`.

### Site configuration

A simple site example configuration to host the SCION configuration resources.
Use a proper OpenAPI configuration and server setup for more complex setups
(the scionproto repository contains a Bazel target to generate boilerplate
for use with a chi-server) or proxy the requests to the SCION control service
if the corresponding OpenAPI endpoint is publicly reachable.

```nginx
server {
        listen 8041 default_server;
        listen [::]:8041 default_server;

        location / {
                root /srv/http/;
                autoindex off;
        }
        location /topology { alias /srv/http/topology.json; }
        location /trcs { alias /srv/http/trcs.json; }
        location /trcs/isd{isd}-b{base}-s{serial} { alias /srv/http/isd{isd}-b{base}-s{serial}.json; }
        location /trcs/isd{isd}-b{base}-s{serial}/blob { alias /srv/http/ISD{isd}-B{base}-S{serial}.trc; }
}
```
 Make sure to replace `{isd}`, `{base}`, and `{serial}` with the values corresponding to
your TRC(s).

### Check the web server

You can test that the web server is working with:

- `curl http://${SERVER_IP}:8041/topology`, and
- `curl http://${SERVER_IP}:8041/trcs/isd{isd}-b{base}-s{serial}/blob`
  (make sure to replace `{isd}`, `{base}`, and `{serial}` with the correct values.)

The former should return the topology of the AS.
The latter should return a file containing the requested TRC.

## Contributing

When contributing, please run `make all` in order to make sure that all targets build and to run the linter.
To generate the `go_deps.bzl` file from scratch, delete it and run `make go_deps.bzl`.
