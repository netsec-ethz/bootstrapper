# Bootstrapper

This repository contains a bootstrapper for network configuration.
It retrieves **hints** from available `zero conf` services to discover the IP address and port
of the **discovery server** serving the actual configuration files over HTTP.

It uses the following hinting mechanisms:
- DHCP option `www-server` and `Vendor-Identifying Vendor Option` [RFC2132],[RFC3925]
- DNS-SRV: DNS service resource records [RFC2782]
- DNS-SD: DNS service discovery [RFC6763]
- mDNS: multicast DNS [RFC6762]

It integrates with SCION by using the same OpenAPI as the control service uses
for exposing TRCs (serving as root certificate) and the topology file
(describing the local SCION topology).

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
Make sure to disable the options you don't need, by default `dnsmasq` is enabled to reply to DNS queries,
but it also has an integrated DHCP server that can be enabled for only specific interfaces or all interfaces.
Make sure to also check how `dnsmasq` interacts with the `resolvconf package` and your local network DHCP setup.

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

```toml
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

```toml
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
  `/srv/http/scion/trcs/ISD{isd}-B{base}-S{serial}.trc`.
- create a link to the *trc* blob containing the TRC file itself at
  `/srv/http/scion/trcs/isd{isd}-b{base}-s{serial}/blob`.

### Site configuration

A simple site example configuration to host the SCION configuration resources.
Use a proper OpenAPI configuration and server setup for more complex setups
(the scionproto repository contains a Bazel target to generate boilerplace
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

### Check the webserver

You can test that the webserver is working with:

- `curl http://${SERVER_IP}:8041/topology`, and
- `curl http://${SERVER_IP}:8041/trcs/isd{isd}-b{base}-s{serial}/blob`
  (make sure to replace `{isd}`, `{base}`, and `{serial}` with the correct values.)

The former should return the topology of the AS.
The latter should return containing the requested TRC.
