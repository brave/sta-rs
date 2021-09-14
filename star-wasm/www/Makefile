
all: build

release: node_modules/webpack
	rm -frv dist
	NODE_ENV=production npm run build:release
	NODE_ENV=production npm ci

build: node_modules/webpack
	npm run build

node_modules/webpack:
	npm install

clean:
	rm -frv dist
	rm -fr node_modules
