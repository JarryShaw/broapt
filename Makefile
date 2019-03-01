.PHONY: docker pipenv download submodule

docker: docker-build docker-run
pipenv: pipenv-update
download: requirements-download
submodule: submodule-clone

pipenv-update:
	pipenv update
	pipenv install --dev
	pipenv clean

pipenv-remove:
	pipenv --rm

requirements-init:
	cd vendor/python && $(MAKE) init

requirements-update:
	cd vendor/python && $(MAKE) update

requirements-download:
	cd vendor/python && $(MAKE) download

requirements-remove:
	cd vendor/python && $(MAKE) remove

docker-build:
	sed "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile > Dockerfile.tmp
	mv Dockerfile.tmp Dockerfile
	docker build --rm --tag broapt .

docker-run:
	docker run -it broapt

submodule-clone:
	cd vendor && $(MAKE) all
