.DEFAULT_GOAL := build

PARALLEL_COUNT=$(shell nproc)

bootstrap:
	mkdir -p ~/.mozbuild
	cd .. && ./mach --no-interactive bootstrap --application-choice browser

build-stock-debug:
	cd .. && MOZCONFIG=mozconfig_stock_debug ./mach build

build-hfiemu-debug:
	cd .. && MOZCONFIG=mozconfig_hfiemu_debug ./mach build

build-debug: build-stock-debug build-hfiemu-debug

build-stock-release:
	cd .. && MOZCONFIG=mozconfig_stock_release ./mach build

build-hfiemu-release:
	cd .. && MOZCONFIG=mozconfig_hfiemu_release ./mach build

build: build-stock-release build-hfiemu-release

clean:
	rm -rf ../ffbuilds