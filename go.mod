module github.com/netsec-ethz/bootstrapper

require (
	github.com/grandcat/zeroconf v1.0.0
	github.com/inconshreveable/log15 v0.0.0-20201112154412-8562bdadbbac
	github.com/insomniacslk/dhcp v0.0.0-20200922210017-67c425063dca
	github.com/mdlayher/ndp v0.10.0
	github.com/miekg/dns v1.1.27
	github.com/pelletier/go-toml v1.8.1-0.20200708110244-34de94e6a887
	gitlab.com/golang-commonmark/puny v0.0.0-20191124015043-9f83538fa04f
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	golang.org/x/sys v0.0.0-20220317061510-51cd9980dadf
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/stretchr/testify v1.6.1 // indirect
	github.com/u-root/u-root v7.0.0+incompatible // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
)

replace github.com/insomniacslk/dhcp => github.com/stapelberg/dhcp v0.0.0-20190429172946-5244c0daddf0

go 1.18
