// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

const bootstrapperSample = `
# The folder where the retrieved topology and certificates are stored (default ".")
sciond_config_dir = "."

# Set the verification behavior of the signature of the configuration file using the TRC (default permissive)
security_mode = "insecure"

# Set the crypto engine to use for the signature verification, options are 'openssl' and 'native' (default native)
crypto_engine = "openssl"

# Discovery mechanisms
[mock]
    # Whether to enable the fake discovery or not (default false)
    # This discovery mechanisms is used for testing purposes
    enable = false
    # The address to return when simulating a network discovery (default "")
    address = ""
[dhcp]
    # Whether to enable DHCP discovery or not (default false)
    enable = false
[dhcpv6]
    # Whether to enable DHCPv6 discovery or not (default false)
    enable = false
    # Set the DHCPv6 Unique Identifier type (default "DUID-LLT")
    DUID_type = "DUID-LL"
    # Set a static, fixed DUID
    # Overrides the DUID_type setting, to be used for setting DUID-EN, DUID-UUID or debugging
    # Fixed hex string for the client DUID, no separators, no 0x prefix:
    #client_id = "0001000100000000deadbeefaabb"
[ipv6]
    # Whether to enable IPv6 Neighbor Discovery Protocol (NDP) for the
    # Router Advertisement DNSSL and RDNS discovery or not (default false)
    enable = false
[dnssd]
    # Whether to enable DNS SRV discovery or not (default false)
    enable_srv = true
    # Whether to enable DNS-SD discovery or not (default false)
    enable_sd = true
    # Whether to enable DNS-NAPTR discovery or not (default false)
    enable_naptr = true
[mdns]
    # Whether to enable mDNS discovery or not (default false)
    enable = true
[log]
    [log.console]
        # Console logging level (debug|info|error) (default info)
        level = "debug"
`
