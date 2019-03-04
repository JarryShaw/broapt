.PHONY: commit docker gitlab pipenv download submodule

commit: gitlab-commit git-commit
docker: docker-build docker-run
gitlab: gitlab-submodule
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

git-commit:
	git pull
	git add .
	git commit -a -S
	git push

submodule-clone:
	cd vendor && $(MAKE) all
	git clone http://202.120.1.158/bysj.git gitlab

gitlab-copy:
	find . ! -name '.git' \
	       ! -iname 'gitlab' \
	       ! -iname 'vendor' -depth 1 -exec cp -rf {} gitlab/xiaojiawei \;
	sed /lfs/d gitlab/xiaojiawei/.gitattributes > gitlab/xiaojiawei/.gitattributes.tmp
	mv gitlab/xiaojiawei/.gitattributes.tmp gitlab/xiaojiawei/.gitattributes
	mkdir -p gitlab/xiaojiawei/vendor
	find vendor ! -iname 'bro' \
	            ! -iname 'Cellar' \
	            ! -iname 'file-extraction' \
	            ! -iname 'zeek' -depth 1 -exec cp -rf {} gitlab/xiaojiawei/vendor \;

gitlab-commit: gitlab-copy
	cd gitlab/xiaojiawei/vendor/file\-extraction && git pull
	cd gitlab/xiaojiawei/vendor/zeek && git pull
	cd gitlab/xiaojiawei && $(MAKE) git-commit

gitlab-submodule: gitlab-copy
	rm -rf gitlab/xiaojiawei/vendor/file\-extraction \
	       gitlab/xiaojiawei/vendor/zeek
	cd gitlab/xiaojiawei/vendor && $(MAKE) all
