.PHONY: build commit docker docker-compose gitlab link pipenv download submodule update

include .env

export PIPENV_VENV_IN_PROJECT
export PIPENV_MAX_DEPTH
export PIPENV_CLEAR

build: build-bro build-broker
commit: gitlab-commit git-commit
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
	pipenv run python -m pip install -U pip setuptools wheel
	pipenv update
	pipenv install --dev
	pipenv clean

pipenv-remove:
	pipenv --rm

requirements-init:
	$(MAKE) -C vendor/python init

requirements-update:
	$(MAKE) -C vendor/python update

requirements-download:
	$(MAKE) -C vendor/python download

requirements-remove:
	$(MAKE) -C vendor/python remove

build-bro:
	$(MAKE) -C build bro

build-broker:
	$(MAKE) -C build broker

docker-build: requirements-download
	$(MAKE) -C cluster clean
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
	docker run --env-file .env \
	           --volume sample:/sample \
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
	find ${REPO_PATH} \
	    ! -iname 'README' \
	    ! -iname '.gitkeep' \
	    ! -iname 'vendor' -depth 1 -print0 | xargs -0 rm -rf
	find ${REPO_PATH}/vendor \
	    ! -iname 'broker' \
	    ! -iname 'file-extraction' \
	    ! -iname 'json' \
		! -iname 'pypcapkit' \
	    ! -iname 'zeek' -depth 1 -print0 | xargs -0 rm -rf

gitlab-copy: gitlab-clean
	# copy .gitmodules
	cat .gitmodules | sed "s/vendor/xiaojiawei\/vendor/" > gitlab/.gitmodules
	# copy top-level files
	find . \
	    ! -iname '.gitmodules' \
	    ! -iname 'Pipfile.lock' -type f -depth 1 -exec cp -rf {} ${REPO_PATH} \;
	# remove git-lfs usage
	sed -i "" /lfs/d ${REPO_PATH}/.gitattributes
	# copy archive
	mkdir -p ${REPO_PATH}/archive
	find archive \
	    -depth 1 -exec cp -rf {} ${REPO_PATH}/archive \;
	# copy build
	mkdir -p ${REPO_PATH}/build
	find build \
	    ! -iname 'venv' -depth 1 -exec cp -rf {} ${REPO_PATH}/build \;
    # copy cluster
	mkdir -p ${REPO_PATH}/cluster
	cp -f \
	    cluster/init.sh \
	    cluster/Makefile ${REPO_PATH}/cluster
	$(MAKE) -C cluster/app build clean vendor
	find cluster -iname 'app' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	$(MAKE) -C cluster/core clean vendor
	find cluster -iname 'core' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	$(MAKE) -C cluster archive
	find cluster -iname 'archive' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	find cluster -iname 'docker' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	find cluster -iname 'utils' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	# copy docker
	cp -rf docker ${REPO_PATH}
	# copy source
	mkdir -p ${REPO_PATH}/source
	$(MAKE) -C source build clean
	find source \
	    ! -iname 'dump' \
	    ! -iname 'logs' \
	    ! -iname '.env' -depth 1 -exec cp -rf {} ${REPO_PATH}/source \;
	# copy vendor
	mkdir -p ${REPO_PATH}/vendor
	find vendor -depth 1 -type f -exec cp -rf {} ${REPO_PATH}/vendor \;
	mkdir -p ${REPO_PATH}/vendor/archive
	find vendor/archive \
	    ! -iname 'build' -depth 1 -exec cp -rf {} ${REPO_PATH}/vendor/archive \;
	mkdir -p ${REPO_PATH}/vendor/python
	find vendor/python -depth 1 -type f -exec cp -rf {} ${REPO_PATH}/vendor/python \;
	mkdir -p ${REPO_PATH}/vendor/python/app
	find vendor/python/app \
	    ! -iname '.venv' -depth 1 -exec cp -rf {} ${REPO_PATH}/vendor/python/app \;
	mkdir -p ${REPO_PATH}/vendor/python/core
	find vendor/python/core \
	    ! -iname '.venv' -depth 1 -exec cp -rf {} ${REPO_PATH}/vendor/python/core \;
	mkdir -p ${REPO_PATH}/vendor/python/src
	find vendor/python/src \
	    ! -iname '.venv' -depth 1 -exec cp -rf {} ${REPO_PATH}/vendor/python/src \;
	mkdir -p ${REPO_PATH}/vendor/tools
	find vendor/tools -depth 1 -exec cp -rf {} ${REPO_PATH}/vendor/tools \;
	# remove unexpected files
	find ${REPO_PATH} \
	    -iname '__pycache__' -or \
	    -iname '*~orig*' -type fd -print0 | xargs -0 rm -rf
	find gitlab \
	    -iname '.DS_Store' -print0 | xargs -0 rm -rf

gitlab-commit: gitlab-copy
	$(MAKE) -C ${REPO_PATH} git-commit

gitlab-submodule: gitlab-copy
	rm -rf ${REPO_PATH}/vendor/broker \
	       ${REPO_PATH}/vendor/file\-extraction \
	       ${REPO_PATH}/vendor/zeek
	$(MAKE) -C ${REPO_PATH}/vendor all
