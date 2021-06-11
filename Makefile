
.PHONY: all bazel build clean gazelle package package_deb package_rpm

all: go_deps.bzl gazelle build test package

build: bazel
#go build -ldflags "-X github.com/netsec-ethz/bootstrapper/config.versionString="$(./.bazel-build-env | awk '{print $2}')

bazel: go_deps.bzl
	rm -f bin/*
	bazel build //:bootstrapper
	cp bazel-bin/bootstrapper bin/

clean:
	bazel clean
	rm -f bin/*

package: build
	bazel build //:scion-bootstrapper-deb
	cp bazel-bin/scion-bootstrapper_*_*.deb bin/

package_deb: package

package_rpm: build
	bazel build //:scion-bootstrapper-rpm
	cp bazel-bin/scion-bootstrapper-*.*.rpm bin/

gazelle: go.mod go_deps.bzl
	bazel run //:gazelle -- update-repos -from_file=go.mod -to_macro=go_deps.bzl%go_deps

define go_deps_boilerplate
# Generated from go.mod by gazelle. DO NOT EDIT
load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_deps():
  pass
endef

go_deps.bzl:
	$(file > ./go_deps.bzl,$(go_deps_boilerplate))

test: build
	bazel test --config=unit --test_output=errors ...

