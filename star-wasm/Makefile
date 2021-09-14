
all: build

build:
	wasm-pack build --target bundler --release

build-nodejs:
	wasm-pack build --target nodejs --release

clean:
	cargo clean
	rm -frv pkg
