module github.com/netsec-ethz/bootstrapper

require (
	github.com/grandcat/zeroconf v1.0.0
	github.com/inconshreveable/log15 v2.16.0+incompatible
	github.com/insomniacslk/dhcp v0.0.0-20250417080101-5f8cf70e8c5f
	github.com/mdlayher/ndp v1.1.0
	github.com/miekg/dns v1.1.65
	github.com/pelletier/go-toml v1.9.5
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.39.0
	golang.org/x/sys v0.32.0
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/u-root/u-root v7.0.0+incompatible // indirect
	gitlab.com/golang-commonmark/puny v0.0.0-20191124015043-9f83538fa04f // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/term v0.31.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/tools v0.32.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace github.com/insomniacslk/dhcp => github.com/stapelberg/dhcp v0.0.0-20190429172946-5244c0daddf0

go 1.24
