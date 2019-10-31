package config

const idSample = "bootstrapper"

const bootstrapperSample = `
# The network interface to use (default "")
Interface = eth0

# The path where the discovered topology is placed (default "")
Topology = sciond/topology.json

# The path where the sciond config will be generated (default "")
SciondConfig = sciond/sd.toml
`

const mechanismIdSample = "mechanisms"

const mechanismsSample = `
DHCP = true

mDNS = true

DNSSD = true

DNSNAPTR = true
`
