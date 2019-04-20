.PHONY: new init install update download clean remove

include .env

export PIPENV_VENV_IN_PROJECT=1
export PIPENV_NO_INHERIT=1
export PIPENV_CLEAR=1

DIR ?= "vendor"

.ONESHELL:
new:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	mkdir -p $(DIR)
	cp -f README.md Makefile .env $(DIR)
	$(MAKE) -C $(DIR) init

.ONESHELL:
init:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	# create pipenv
	pipenv --python 3.5 || true

.ONESHELL:
install: init
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	# install dependencies
	# pipenv install ...
	# pipenv install --dev ...

.ONESHELL:
update:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	# update pipenv
	pipenv update
	pipenv install
	pipenv clean
	# create requirements.txt
	echo "# Python packages" > requirements.txt
	pipenv run python -m pip show pip        | grep Version | sed "s/Version: \(.*\)*/pip==\1/"        >> requirements.txt
	pipenv run python -m pip show setuptools | grep Version | sed "s/Version: \(.*\)*/setuptools==\1/" >> requirements.txt
	pipenv run python -m pip show wheel      | grep Version | sed "s/Version: \(.*\)*/wheel==\1/"      >> requirements.txt
	echo >> requirements.txt
	echo "# Python dependencies" >> requirements.txt
	pipenv run python -m pip freeze >> requirements.txt

.ONESHELL:
download: update clean
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	pipenv run python -m pip download --requirement=requirements.txt \
                              		  --platform=manylinux1_x86_64 \
                              		  --python-version=35 \
                              		  --implementation=cp \
                              		  --dest=download \
                              		  --no-deps

.ONESHELL:
clean:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	find download -iname '*.tar.gz' -print0 | xargs -0 rm -f
	find download -iname '*.whl' -print0 | xargs -0 rm -f

.ONESHELL:
remove:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	pipenv --rm
