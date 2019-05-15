.PHONY: init clean docker vendor

init: mkdir-dump mkdir-logs
clean: clean-dump clean-logs clean-state

docker:
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag broapt-core .
	docker system prune --volumes -f

vendor:
	rm -rf vendor
	mkdir -p vendor vendor/{archive,python}
	wget http://download.opensuse.org/repositories/network:bro/CentOS_7/network:bro.repo \
	    -O vendor/archive/network-bro.repo
	$(MAKE) -C ../../vendor/python/core download
	find ../../vendor/python/core/download -iname '*.tar.gz' -type f -exec cp -f {} vendor/python \;
	find ../../vendor/python/core/download -iname '*.whl' -type f -exec cp -f {} vendor/python \;

clean-dump:
	if [ -d /home/traffic/log/extract ]; then \
	    rm -rf /home/traffic/log/extract; \
	    mkdir -p /home/traffic/log/extract; \
	else \
	    find ../dump -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find ../dump -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-logs: clean-logs-local clean-logs-processed

clean-logs-local:
	find . -iname '*.log' -print0 | xargs -0 rm -f

clean-logs-processed:
	if [ -d /home/traffic/log/bro ]; then \
	    rm -f /home/traffic/log/bro/*.lock; \
	    > /home/traffic/log/bro/http.log; \
	    > /home/traffic/log/bro/processed_file.log; \
	    > /home/traffic/log/bro/processed_info.log; \
	    > /home/traffic/log/bro/processed_mime.log; \
	    > /home/traffic/log/bro/processed_time.log; \
	    for file in $$(ls /home/traffic/log/bro) ; do \
	        [ -d "/home/traffic/log/bro/$${file}" ] && \
		    [ "/home/traffic/log/bro/$${file}" != "tmp" ] && \
		    rm -rf "/home/traffic/log/bro/$${file}" || true; \
	    done \
	else \
	    rm -f ../logs/*.lock; \
	    > ../logs/http.log; \
	    > ../logs/processed_file.log; \
	    > ../logs/processed_info.log; \
	    > ../logs/processed_mime.log; \
	    > ../logs/processed_time.log; \
	    find ./logs \
		    ! -iname 'tmp' \
		    ! -iname 'api' -type d -depth 1 -print0 | xargs -0 rm -rf; \
	fi

clean-nohup:
	rm -f nohup.out

clean-state:
	rm -rf source/.state

mkdir-dump:
	mkdir -p ../dump

mkdir-logs:
	mkdir -p ../logs
