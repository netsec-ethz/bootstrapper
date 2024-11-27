
.PHONY: all bazel bootstrappper build go_build install_deps clean realclean package package_deb package_rpm

build: install_deps bazel

go_build:
	@go build -o scion-bootstrapper -ldflags "-X github.com/netsec-ethz/bootstrapper/config.versionString="$$(git describe --tags --dirty --always)

bootstrapper:
	@if [ -n "$${OS}" ] ; then \
	  UNAME_OS="$${OS}"; \
	else \
	  UNAME_OS=$$(uname --kernel-name); \
	fi; \
	if [ "$${UNAME_OS}" = "Linux" ] ; then \
	  make -s build; \
	elif [ "$${UNAME_OS}" = "Windows_NT" ] ; then \
	  make.exe -s go_build; \
	  cp scion-bootstrapper scion-bootstrapper.exe; \
	else \
	  make -s go_build; \
	fi;

install_deps:
	@if [ -z "$${CC}" ] ; then \
	  if [ ! -x "$$(command -v gcc)" ]; then \
	    echo "Cannot find gcc or CC; set the CC environment variable or make sure gcc is on your PATH."; \
	  else \
	    exit 0; \
	  fi; \
	else \
	  exit 0; \
	fi; \
	apt-get install build-essential 2>/dev/null; \
	test $$? -eq 0 || echo "Install build tools?\nsudo apt-get install build-essential" && sudo apt-get install build-essential

bazel: go_deps.bzl
	rm -f bin/*
	@if [ -z "$${CC}" ] ; then \
	  if [ ! -x "$$(command -v gcc)" ]; then \
	    echo "Cannot find gcc or CC; set the CC environment variable or make sure gcc is on your PATH." && exit 1; \
	  fi; \
	fi;
	./.bazel-build-env
	bazel build //:bootstrapper
	@cp `bazel aquery  'outputs(".*bin/bootstrapper", //:bootstrapper)' --output=text 2>/dev/null | grep "Outputs" | sed -r 's/\s*Outputs: \[(.*)\]/\1/'` bin/
	@ln -sf ./bin/bootstrapper ./scion-bootstrapper

all: bootstrapper test package

clean:
	bazel clean
	rm -f ./bin/*

realclean: clean
	bazel clean --expunge
	rm -f ./MODULE.bazel*
	rm -f ./go_deps.bzl

package: package_deb

package_deb: build
	@if [ ! -x "$$(command -v python3)" ]; then \
	  echo "Cannot find python3 on your PATH."; \
	  apt-get install python3 &>/dev/null; \
	  test $$? -eq 0 || echo "Install python3?\nsudo apt-get install python3" && sudo apt-get install python3; \
	fi;
	bazel build //:scion-bootstrapper-deb
	cp bazel-bin/scion-bootstrapper_*_*.deb bin/

package_rpm: build
	@if [ ! -x "$$(command -v rpmbuild)" ]; then \
	  echo "Cannot find rpmbuild on your PATH."; \
	  apt-get install rpm &>/dev/null; \
	  test $$? -eq 0 || echo "Install rpm toolchain?\nsudo apt-get install rpm" && sudo apt-get install rpm; \
	fi;
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
	bazel clean --expunge

test: build
	@if [ ! -x "$$(command -v "scion-pki")" ]; then \
	  echo "Cannot find scion-pki; make sure scion-pki is on your PATH otherwise the tests relying on it will fail."; \
	fi;
	bazel test --test_output=errors //hinting:go_default_test //fetcher:go_default_test //config:go_default_test
	# Do not filter on unit tag for now, as doing so forces all loaded packages
	# to satisfy their dependencies, which is not desirable for pkg_rpm
	# which forces to have a full rpm toolchain loaded, even when the target
	# is not executed. Explicitly list all test targets.
	#bazel test --config=unit --test_output=errors ...

