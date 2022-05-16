module github.com/netsec-ethz/bootstrapper

require (
	github.com/grandcat/zeroconf v1.0.0
	github.com/inconshreveable/log15 v0.0.0-20201112154412-8562bdadbbac
	github.com/insomniacslk/dhcp v0.0.0-20211209223715-7d93572ebe8e
	github.com/mdlayher/ndp v0.10.0
	github.com/miekg/dns v1.1.41
	github.com/pelletier/go-toml v1.8.1-0.20200708110244-34de94e6a887
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	golang.org/x/sys v0.0.0-20220317061510-51cd9980dadf
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/u-root/uio v0.0.0-20210528114334-82958018845c // indirect
	gitlab.com/golang-commonmark/puny v0.0.0-20191124015043-9f83538fa04f // indirect
)

replace github.com/insomniacslk/dhcp => github.com/FR4NK-W/dhcp v0.0.0-20220119180841-3c283ff8b7dd

replace github.com/grandcat/zeroconf => github.com/FR4NK-W/zeroconf v0.0.0-20220516150908-9a157234cba8

go 1.18
