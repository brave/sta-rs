
all: build

build:
	cargo build --release
	wasm-pack build --target bundler --release

clean:
	cargo clean
	rm -frv pkg
