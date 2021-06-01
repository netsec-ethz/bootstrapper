module github.com/netsec-ethz/bootstrapper

require (
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/grandcat/zeroconf v1.0.0
	github.com/inconshreveable/log15 v0.0.0-20201112154412-8562bdadbbac
	github.com/insomniacslk/dhcp v0.0.0-20200922210017-67c425063dca
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/miekg/dns v1.1.27
	github.com/pelletier/go-toml v1.8.1-0.20200708110244-34de94e6a887
	github.com/stretchr/testify v1.6.1 // indirect
	github.com/u-root/u-root v7.0.0+incompatible // indirect
	golang.org/x/net v0.0.0-20200927032502-5d4f70055728
	golang.org/x/sys v0.0.0-20200916030750-2334cc1a136f
)

replace github.com/insomniacslk/dhcp => github.com/stapelberg/dhcp v0.0.0-20190429172946-5244c0daddf0

go 1.14
