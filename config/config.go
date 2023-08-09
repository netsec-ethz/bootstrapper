// Copyright 2020 Anapaya Systems
// Copyright 2021 ETH Zurich
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

// Package config contains the configuration of bootstrapper.
package config

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"

	"github.com/inconshreveable/log15"
	"github.com/pelletier/go-toml"

	"github.com/netsec-ethz/bootstrapper/hinting"
)

const (
	// DefaultLogLevel is the default log level.
	DefaultLogLevel = "info"
)

type SecurityMode string

const (
	Strict     SecurityMode = "strict"     // only store a TRC if it validates against an existing TRC update chain
	Permissive SecurityMode = "permissive" // only store a TRC if it does not conflict with an existing TRC update chain
	Insecure   SecurityMode = "insecure"   // store any TRC, mark it as insecure, don't validate the topology signature
)

var (
	version       bool
	versionString string
	helpConfig    bool
	configPath    string
	IfaceName     string
)

type Config struct {
	InterfaceName   string                          `toml:"iface,omitempty"`
	SciondConfigDir string                          `toml:"sciond_config_dir"`
	SecurityMode    SecurityMode                    `toml:"security_mode,omitempty"`
	MOCK            hinting.MOCKHintGeneratorConf   `toml:"mock"`
	DHCP            hinting.DHCPHintGeneratorConf   `toml:"dhcp"`
	DHCPv6          hinting.DHCPv6HintGeneratorConf `toml:"dhcpv6"`
	IPv6            hinting.IPv6HintGeneratorConf   `toml:"ipv6"`
	DNSSD           hinting.DNSHintGeneratorConf    `toml:"dnssd"`
	MDNS            hinting.MDNSHintGeneratorConf   `toml:"mdns"`
	Logging         LogConfig                       `toml:"log,omitempty"`
	CryptoEngine	string                          `toml:"crypto_engine,omitempty"`
}

func (cfg Config) WorkingDir() string {
	return filepath.Join(cfg.SciondConfigDir, "bootstrapper")
}

// LogConfig is the configuration for the logger.
type LogConfig struct {
	Console ConsoleConfig `toml:"console,omitempty"`
}

// ConsoleConfig is the config for the console logger.
type ConsoleConfig struct {
	// Level of console logging (defaults to DefaultLogLevel).
	Level string `toml:"level,omitempty"`
}

func AddFlags() {
	flag.BoolVar(&version, "version", false, "Output version information.")
	flag.BoolVar(&helpConfig, "help-config", false, "Output a commented sample config file.")
	flag.StringVar(&configPath, "config", "", "Config file path.")
	flag.StringVar(&IfaceName, "iface", "", "The interface used to probe the network.")
	flag.Usage = Usage
}

// Usage outputs message help to stdout.
func Usage() {
	fmt.Printf("Usage: %[1]s -config <FILE> -iface <interface>\n"+
		"   or: %[1]s -help-config\n"+
		"   or: %[1]s -version\n\nArguments:\n",
		os.Args[0])
	flag.CommandLine.SetOutput(os.Stdout)
	flag.PrintDefaults()
}

func CheckFlags(cfg *Config) (int, bool) {
	if version {
		fmt.Printf("  Bootstrapper version: %s\n", versionString)
		return 0, false
	}
	if helpConfig {
		cfg.Sample(os.Stdout)
		return 0, false
	}
	if configPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "Err: Missing config file")
		flag.Usage()
		return 1, false
	}
	return 0, true
}

func LoadFile(cfg *Config) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	err = toml.NewDecoder(bytes.NewReader(raw)).Strict(true).Decode(cfg)
	return err
}

func (cfg *Config) InitDefaults() {
	if cfg.Logging.Console.Level == "" {
		cfg.Logging.Console.Level = DefaultLogLevel
	}
	if cfg.SciondConfigDir == "" {
		cfg.SciondConfigDir = "."
	}
	if cfg.SecurityMode == "" {
		cfg.SecurityMode = Permissive
	}
	if cfg.CryptoEngine == "" {
		cfg.CryptoEngine = "native"
	}
	if cfg.InterfaceName == "" && (cfg.DHCPv6.Enable || cfg.IPv6.Enable || cfg.DHCP.Enable || cfg.MDNS.Enable) {
		log15.Warn("iface flag not set, recommended when IPv6, DHCP or mDNS hinting is enabled")
		iface, err := getDefaultInterface()
		if err != nil {
			log15.Error(err.Error())
		} else {
			cfg.InterfaceName = iface.Name
			log15.Info("Using default primary interface for requests",
				"interface", cfg.InterfaceName)
		}
	}
}

func getDefaultInterface() (net.Interface, error) {
	if ifaces, err := net.Interfaces(); err == nil {
		sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Index < ifaces[j].Index })
		for _, iface := range ifaces {
			if (iface.Flags & net.FlagLoopback) != 0 {
				continue
			}
			if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagBroadcast) != 0 {
				return iface, nil
			}
		}
	}
	return net.Interface{}, fmt.Errorf("no active external broadcast interface found")
}

func (cfg *Config) Validate() error {
	// Validate log level
	_, err := log15.LvlFromString(cfg.Logging.Console.Level)
	if err != nil {
		return fmt.Errorf("unknown log level %s\n", cfg.Logging.Console.Level)
	}

	// Validate iface
	if cfg.DHCPv6.Enable || cfg.IPv6.Enable || cfg.DHCP.Enable || cfg.MDNS.Enable {
		_, err := net.InterfaceByName(cfg.InterfaceName)
		if err != nil {
			return fmt.Errorf("valid interface value required when IPv6, DHCP or mDNS hinting enabled: %w", err)
		}
	}
	return nil
}

func (cfg *Config) Sample(dst io.Writer) {
	_, err := dst.Write([]byte(bootstrapperSample))
	if err != nil {
		panic(fmt.Errorf("unable to write string to %v err=%w", dst, err))
	}
}

func (cfg *Config) ConfigName() string {
	return "bootstrapper_config"
}
