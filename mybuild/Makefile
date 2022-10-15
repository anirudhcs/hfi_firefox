.DEFAULT_GOAL := build

PARALLEL_COUNT=$(shell nproc)

bootstrap:
	mkdir -p ~/.mozbuild
	cd .. && ./mach --no-interactive bootstrap --application-choice browser

build-stock-debug:
	cd .. && MOZCONFIG=mozconfig_stock_debug ./mach build

build-boundschecks-debug:
	cd .. && MOZCONFIG=mozconfig_boundschecks_debug ./mach build

build-masking-debug:
	cd .. && MOZCONFIG=mozconfig_masking_debug ./mach build

build-hfiemu-debug:
	cd .. && MOZCONFIG=mozconfig_hfiemu_debug ./mach build

build-hfiemu2-debug:
	cd .. && MOZCONFIG=mozconfig_hfiemu2_debug ./mach build

build-debug: build-stock-debug build-boundschecks-debug build-masking-debug build-hfiemu-debug build-hfiemu2-debug

build-stock-release:
	cd .. && MOZCONFIG=mozconfig_stock_release ./mach build

build-boundschecks-release:
	cd .. && MOZCONFIG=mozconfig_boundschecks_release ./mach build

build-stock-maskingelease:
	cd .. && MOZCONFIG=mozconfig_masking_release ./mach build

build-hfiemu-release:
	cd .. && MOZCONFIG=mozconfig_hfiemu_release ./mach build

build-hfiemu2-release:
	cd .. && MOZCONFIG=mozconfig_hfiemu2_release ./mach build

build: build-stock-release build-boundschecks-release build-masking-release build-hfiemu-release build-hfiemu2-release

clean:
	rm -rf ../ffbuilds