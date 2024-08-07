.PHONY: build commit docker docker-compose gitlab link pipenv download submodule update run

-include .env

export PIPENV_VENV_IN_PROJECT
export PIPENV_MAX_DEPTH
export PIPENV_CLEAR

setup:
	$(MAKE) -C source setup
	$(MAKE) -C docs setup

run:
	$(MAKE) -C source run

stop:
	$(MAKE) -C source stop

kill:
	$(MAKE) -C source kill

build: build-bro build-broker
commit: gitlab-commit git-commit
docker: docker-build docker-run
docker-compose: docker-compose-daemon docker-compose-exec docker-compose-stop
download: requirements-download
gitlab: gitlab-submodule
link: submodule-link
pipenv: pipenv-init
update: pipenv-update download submodule-pull

submodule:
	git submodule init
	git submodule update

clean:
	$(MAKE) -C source clean

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
	$(MAKE) -C vendor/python root-download

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
	git clone https://gitlab.sjtu.edu.cn/xiaojiawei/broapt.git gitlab

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
	    ! -iname '.git' \
	    ! -iname '.gitkeep' \
	    ! -iname 'vendor' -depth 1 -print0 | xargs -0 rm -rf
	find ${REPO_PATH}/vendor \
	    ! -iname 'broker' \
	    ! -iname 'file-extraction' \
	    ! -iname 'tools' \
	    ! -iname 'zeek' -depth 1 -print0 | xargs -0 rm -rf
	find ${REPO_PATH}/vendor/tools \
	    ! -iname 'AndroPyTool' \
	    ! -iname 'bro-phishing' \
	    ! -iname 'elfparser' \
	    ! -iname 'JaSt' \
	    ! -iname 'MaliciousMacroBot' \
	    ! -iname 'smtp-url-analysis' -depth 1 -print 0 | xargs -0 rm -rf

gitlab-copy: gitlab-clean
	# copy .gitmodules
	cat .gitmodules | sed "/gitlab/d" > gitlab/.gitmodules
	# copy top-level files
	find . \
	    ! -iname '.gitmodules' \
	    ! -iname 'Pipfile.lock' -type f -depth 1 -exec cp -rf {} ${REPO_PATH} \;
	# remove git-lfs usage
	sed -i "" /lfs/d ${REPO_PATH}/.gitattributes
    # copy cluster
	mkdir -p ${REPO_PATH}/cluster
	cp -f \
	    cluster/init.sh \
	    cluster/Makefile ${REPO_PATH}/cluster
	$(MAKE) -C cluster/app clean vendor
	find cluster -iname 'app' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	$(MAKE) -C cluster/core clean vendor
	find cluster -iname 'core' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	$(MAKE) -C cluster/daemon build
	$(MAKE) -C cluster/daemon clean
	find cluster -iname 'daemon' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	$(MAKE) -C cluster archive
	find cluster -iname 'archive' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	find cluster -iname 'docker' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	find cluster -iname 'utils' -depth 1 -exec cp -rf {} ${REPO_PATH}/cluster \;
	# copy docs
	mkdir -p ${REPO_PATH}/docs
	find docs \
	    -depth 1 -exec cp -rf {} ${REPO_PATH}/docs \;
	# copy source
	mkdir -p ${REPO_PATH}/source
	$(MAKE) -C source build
	$(MAKE) -C source clean
	find source \
	    ! -iname 'dump' \
	    ! -iname 'logs' \
	    ! -iname '.env' -depth 1 -exec cp -rf {} ${REPO_PATH}/source \;
	# copy vendor
	mkdir -p ${REPO_PATH}/vendor
	find vendor -depth 1 -type f -exec cp -rf {} ${REPO_PATH}/vendor \;
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
	$(MAKE) -C $(REPO_PATH) submodule
