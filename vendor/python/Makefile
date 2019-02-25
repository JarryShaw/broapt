.PHONY: init update download remove

.ONESHELL:
init:
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	mv ../../Pipfile ../../Pipfile.tmp
	pipenv --python 3.6
	pipenv install dpkt pypcapkit
	mv ../../Pipfile.tmp ../../Pipfile

.ONESHELL:
update:
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	pipenv update
	pipenv install
	pipenv clean
	echo "# Python packages" > requirements.txt
	pipenv run python -m pip show pip        | grep Version | sed "s/Version: \(.*\)*/pip==\1/"        >> requirements.txt
	pipenv run python -m pip show setuptools | grep Version | sed "s/Version: \(.*\)*/setuptools==\1/" >> requirements.txt
	pipenv run python -m pip show wheel      | grep Version | sed "s/Version: \(.*\)*/wheel==\1/"      >> requirements.txt
	echo >> requirements.txt
	echo "# Python dependencies" >> requirements.txt
	pipenv run python -m pip freeze >> requirements.txt

.ONESHELL:
download: update
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	pipenv run python -m pip download --requirement=requirements.txt \
                              		  --platform=manylinux1_x86_64 \
                              		  --python-version=36 \
                              		  --implementation=cp \
                              		  --dest=download \
                              		  --no-deps

.ONESHELL:
remove:
	cd $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
	rm -f *.tar.gz *.whl
