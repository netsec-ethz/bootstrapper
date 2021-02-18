# Client bootstrap service

This file contains configuration options and provide some instructions to
get started.

## Nginx web server

After having installed Nginx, the network admin can follow these steps to
expose the endpoints needed by the bootstrapper:

- copy the site configuration to `/etc/nginx/sites-available` and enable it by creating
  a link that points to `/etc/nginx/sites-available/scion` in `/etc/nginx/sites-enabled`,
- create a link to the topology at `/srv/http/scion/discovery/v1/topology.json`, and
- create a link to a *tar* archive containing the TRCs to serve at
  `/srv/http/scion/discovery/v1/trcs.tar`.

### Site configuration

A simple site configuration to host the SCION configuration resources.

```nginx
server {
      listen 8041 default_server;
      listen [::]:8041 default_server;

      location / {
              root /srv/http/;
              autoindex on;
              autoindex_format json;
      }
}
```

### Check the webserver

You can test that the webserver is working with:

- `curl http://${SERVER_IP}:8041/scion/discovery/v1/topology.json`, and
- `curl http://${SERVER_IP}:8041/scion/discovery/v1/trcs.tar`

The former should return the topology of the AS.
The latter should return an archive containing the served TRCs.

## Discovery mechanisms

### DHCP (dnsmasq)

For example, with `dnsmasq`, an option 72 "Default WWW server" can be done by
adding the following line to `/etc/dnsmasq.conf`: `dhcp-option=72,<webserverIP>`.
Note that `dnsmasq` does not support DHCP option 72 `www-server` by default,
`https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html`, supported DHCP options are registered in `dhcp-common.c`.
`dhcpd` supports the option by default, `https://github.com/koenning/isc-dhcpd/blob/master/common/tables.c`.

### mDNS (avahi)

Put the following configuration to `/etc/avahi/services/sciondiscovery.service`:

```xml
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">%h</name>
  <service>
    <type>_sciondiscovery._tcp</type>
    <port>8041</port>
  </service>
</service-group>
```

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

