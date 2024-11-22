
.PHONY: all bazel build clean realclean package package_deb package_rpm

build: bazel
#go build -ldflags "-X github.com/netsec-ethz/bootstrapper/config.versionString="$(./.bazel-build-env | awk '{print $2}')

bazel: go_deps.bzl
	rm -f bin/*
	./.bazel-build-env
	bazel build //:bootstrapper
	cp `bazel aquery  'outputs(".*bin/bootstrapper", //:bootstrapper)' --output=text 2>/dev/null | grep "Outputs" | sed -r 's/\s*Outputs: \[(.*)\]/\1/'` bin/
	ln -sf ./bin/bootstrapper ./scion-bootstrapper

all: build test package

clean:
	bazel clean
	rm -f bin/*

realclean: clean
	bazel clean --expunge
	rm -r ~/.cache/bazel
	rm -rf ./bazel-*
	rm -f ./MODULE.bazel*
	rm -f go_deps.bzl

package: package_deb

package_deb: build
	bazel build //:scion-bootstrapper-deb
	cp bazel-bin/scion-bootstrapper_*_*.deb bin/

package_rpm: build
	bazel build //:scion-bootstrapper-rpm
	cp bazel-bin/scion-bootstrapper-*.*.rpm bin/

darwin:
	@echo "Experimental"
	env GOOS=darwin go build -o scion-bootstrapper -ldflags "-X github.com/netsec-ethz/bootstrapper/config.versionString="$(./.bazel-build-env | awk '{print $2}')

windows:
	@echo "Experimental"
	env GOOS=windows go build -o scion-bootstrapper.exe -ldflags "-X github.com/netsec-ethz/bootstrapper/config.versionString="$(./.bazel-build-env | awk '{print $2}')

define go_deps_boilerplate
# Generated from go.mod by gazelle. DO NOT EDIT
load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_deps():
  pass
endef

go_deps.bzl: go.mod
ifeq (,$(wildcard go_deps.bzl))
	$(file > ./go_deps.bzl,$(go_deps_boilerplate))
endif
	bazel run //:gazelle -- update-repos -from_file=go.mod -to_macro=go_deps.bzl%go_deps -prune
	rm -rf ./bazel-*
	rm -r ~/.cache/bazel

test: build
	bazel test --config=unit --test_output=errors ...

