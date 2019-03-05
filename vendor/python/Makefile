.PHONY: init update download clean remove

.ONESHELL:
init:
	set -ex
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	# remove top-level Pipfile temporarily
	mv ../../Pipfile ../../Pipfile.tmp
	# create pipenv
	pipenv --python 3.5
	pipenv install dpkt "pypcapkit>=0.13.3.post2" python-magic
	# reset top-level Pipfile
	mv ../../Pipfile.tmp ../../Pipfile

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
