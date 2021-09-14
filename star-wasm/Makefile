
all: build

build:
	cargo build --release
	wasm-pack build --target bundler --release

build-nodejs:
	cargo build --release
	wasm-pack build --target nodejs --release

clean:
	cargo clean
	rm -frv pkg
