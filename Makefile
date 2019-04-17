.PHONY: build commit docker docker-compose gitlab link pipenv download submodule update

export PIPENV_VENV_IN_PROJECT=1
export PIPENV_CLEAR=1

build: build-bro build-broker
commit: requirements-download f2format gitlab-commit git-commit
docker: docker-build docker-run
docker-compose: docker-compose-daemon docker-compose-exec docker-compose-stop
download: requirements-download
gitlab: gitlab-submodule
link: submodule-link
pipenv: pipenv-init
submodule: submodule-clone
update: pipenv-update download submodule-pull

pipenv-init:
	pipenv --python 3.7
	pipenv install --dev

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

build-bro:
	cd build && $(MAKE) bro

build-broker:
	cd build && $(MAKE) broker

docker-build: requirements-download
	cd source && $(MAKE) clean
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag broapt .
	$(MAKE) docker-prune

docker-compose-up: docker-build
	docker-compose up

docker-compose-daemon: docker-build
	docker-compose up -d

docker-compose-exec:
	docker-compose exec broapt bash

docker-compose-stop:
	docker-compose stop

docker-prune:
	docker system prune --volumes -f

docker-run:
	docker run --volume sample:/sample \
	           --volume test:/test \
	           --volume vendor:/vendor -it broapt

git-commit:
	git pull
	git add .
	git commit -a -S
	git push

submodule-build:
	cd vendor && $(MAKE) build

submodule-clone:
	cd vendor && $(MAKE) all
	git clone http://202.120.1.158/bysj.git gitlab

submodule-link:
	cd vendor && $(MAKE) link

submodule-pull:
	cd vendor/broker && git pull
	cd vendor/file\-extraction && git pull
	cd vendor/json && git pull
	cd vendor/pypcapkit && git pull
	cd vendor/zeek && git pull

gitlab-clean:
	find gitlab/xiaojiawei \
	    ! -iname 'README' \
	    ! -iname '.gitkeep' \
	    ! -iname 'vendor' -depth 1 -print0 | xargs -0 rm -rf
	find gitlab/xiaojiawei/vendor \
	    ! -iname 'broker' \
	    ! -iname 'file-extraction' \
	    ! -iname 'json' \
		! -iname 'pypcapkit' \
	    ! -iname 'zeek' -depth 1 -print0 | xargs -0 rm -rf

gitlab-copy: gitlab-clean
	# copy top-level files
	find . -type f -depth 1 -exec cp -rf {} gitlab/xiaojiawei \;
	# remove git-lfs usage
	sed -i "" /lfs/d gitlab/xiaojiawei/.gitattributes
	# copy archive
	mkdir -p gitlab/xiaojiawei/archive
	find archive \
	    -depth 1 -exec cp -rf {} gitlab/xiaojiawei/archive \;
	# copy build
	mkdir -p gitlab/xiaojiawei/build
	find build \
	    ! -iname 'venv' -depth 1 -exec cp -rf {} gitlab/xiaojiawei/build \;
	# copy docker
	cp -rf docker gitlab/xiaojiawei
	# copy source
	mkdir -p gitlab/xiaojiawei/source
	find source \
	    ! -iname '*.log' \
	    ! -iname '.state' \
	    ! -iname 'contents' \
	    ! -iname 'dumps' \
	    ! -iname 'extract_files' -depth 1 -exec cp -rf {} gitlab/xiaojiawei/source \;
	# copy vendor
	mkdir -p gitlab/xiaojiawei/vendor
	find vendor \
	    ! -iname 'bro*' \
	    ! -iname 'broker' \
	    ! -iname 'Cellar' \
	    ! -iname 'file-extraction' \
	    ! -iname 'json' \
	    ! -iname 'pypcapkit' \
	    ! -iname 'zeek' \
	    ! -iname 'venv' -depth 1 -exec cp -rf {} gitlab/xiaojiawei/vendor \;
	# remove unexpected files
	find gitlab/xiaojiawei \
	    -iname '__pycache__' -or \
	    -iname '*~orig*' -type fd -print0 | xargs -0 rm -rf
	find gitlab \
	    -iname '.DS_Store' -print0 | xargs -0 rm -rf

gitlab-commit: gitlab-copy
	cd gitlab/xiaojiawei/vendor/broker && git pull
	cd gitlab/xiaojiawei/vendor/file\-extraction && git pull
	cd gitlab/xiaojiawei/vendor/json && git pull
	cd gitlab/xiaojiawei/vendor/pypcapkit && git pull
	cd gitlab/xiaojiawei/vendor/zeek && git pull
	cd gitlab/xiaojiawei && $(MAKE) git-commit

gitlab-submodule: gitlab-copy
	rm -rf gitlab/xiaojiawei/vendor/broker \
	       gitlab/xiaojiawei/vendor/file\-extraction \
	       gitlab/xiaojiawei/vendor/json \
	       gitlab/xiaojiawei/vendor/pypcapkit \
	       gitlab/xiaojiawei/vendor/zeek
	cd gitlab/xiaojiawei/vendor && $(MAKE) all

f2format:
	rm -rf source/python
	cp -rf source/python-dev source/python
	pipenv run f2format \
	    --no-archive \
	    --encoding='UTF-8' \
	    --python='3.7' source/python
