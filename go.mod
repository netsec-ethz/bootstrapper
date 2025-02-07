module github.com/netsec-ethz/bootstrapper

require (
	github.com/grandcat/zeroconf v1.0.0
	github.com/inconshreveable/log15 v0.0.0-20201112154412-8562bdadbbac
	github.com/insomniacslk/dhcp v0.0.0-20200922210017-67c425063dca
	github.com/mdlayher/ndp v0.10.0
	github.com/miekg/dns v1.1.27
	github.com/pelletier/go-toml v1.9.5
	github.com/stretchr/testify v1.9.0
	golang.org/x/net v0.34.0
	golang.org/x/sys v0.29.0
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/u-root/u-root v7.0.0+incompatible // indirect
	gitlab.com/golang-commonmark/puny v0.0.0-20191124015043-9f83538fa04f // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/insomniacslk/dhcp => github.com/stapelberg/dhcp v0.0.0-20190429172946-5244c0daddf0

go 1.22.0
