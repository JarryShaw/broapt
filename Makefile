.PHONY: commit docker docker-compose gitlab pipenv download submodule

commit: requirements-download gitlab-commit git-commit
docker: docker-build docker-run
docker-compose: docker-compose-daemon docker-compose-exec docker-compose-stop
download: requirements-download
gitlab: gitlab-submodule
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

docker-build:
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

submodule-pull:
	cd vendor/broker && git pull
	cd vendor/file\-extraction && git pull
	cd vendor/zeek && git pull

gitlab-clean:
	find gitlab/xiaojiawei \
	    ! -iname 'README' \
	    ! -iname '.gitkeep' \
	    ! -iname 'vendor' -depth 1 -print0 | xargs -0 rm -rf
	find gitlab/xiaojiawei/vendor \
	    ! -iname 'broker' \
	    ! -iname 'file-extraction' \
	    ! -iname 'zeek' -depth 1 -print0 | xargs -0 rm -rf

gitlab-copy: gitlab-clean
	find . -type f -depth 1 -exec cp -rf {} gitlab/xiaojiawei \;
	sed -i "" /lfs/d gitlab/xiaojiawei/.gitattributes
	mkdir -p gitlab/xiaojiawei/source
	find source \
	    ! -iname '*.log' \
		! -iname '.state' \
		! -iname 'contents' \
		! -iname 'extract_files' -depth 1 -exec cp -rf {} gitlab/xiaojiawei/source \;
	mkdir -p gitlab/xiaojiawei/vendor
	find vendor \
	    ! -iname 'bro' \
		! -iname 'broker' \
		! -iname 'Cellar' \
		! -iname 'file-extraction' \
		! -iname 'zeek' \
		! -iname 'venv' -depth 1 -exec cp -rf {} gitlab/xiaojiawei/vendor \;
	find gitlab/xiaojiawei \
		-iname '__pycache__' -or \
		-iname '*~orig*' -type fd -print0 | xargs -0 rm -rf
	find gitlab \
	    -iname '.DS_Store' -print0 | xargs -0 rm -rf

gitlab-commit: gitlab-copy
	cd gitlab/xiaojiawei/vendor/broker && git pull
	cd gitlab/xiaojiawei/vendor/file\-extraction && git pull
	cd gitlab/xiaojiawei/vendor/zeek && git pull
	cd gitlab/xiaojiawei && $(MAKE) git-commit

gitlab-submodule: gitlab-copy
	rm -rf gitlab/xiaojiawei/vendor/broker \
	       gitlab/xiaojiawei/vendor/file\-extraction \
	       gitlab/xiaojiawei/vendor/zeek
	cd gitlab/xiaojiawei/vendor && $(MAKE) all
