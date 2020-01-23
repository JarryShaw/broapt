.PHONY: init clean docker vendor

init: mkdir-dump mkdir-logs
clean: clean-api clean-build clean-dump clean-logs

docker:
	sed -i "" "s/LABEL version.*/LABEL version=$(shell date +%Y.%m.%d)/" Dockerfile
	docker build --rm --tag broapt-app .
	docker system prune --volumes -f

vendor:
	rm -rf vendor/python
	mkdir -p vendor vendor/python
	$(MAKE) -C ../../vendor/python/app download
	find ../../vendor/python/app/download -iname '*.tar.gz' -type f -exec cp -f {} vendor/python \;
	find ../../vendor/python/app/download -iname '*.whl' -type f -exec cp -f {} vendor/python \;

clean-build:
	rm -rf build dist

clean-dump:
	if [ -d /home/traffic/log/extract ]; then \
	    rm -rf /home/traffic/log/extract; \
	    mkdir -p /home/traffic/log/extract; \
	else \
	    find ../dump -depth 1 -type d -print0 | xargs -0 rm -rf; \
	    find ../dump -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-logs:
	if [ -d /home/traffic/log/bro ]; then \
	    rm -f /home/traffic/log/bro/*.lock; \
	    > /home/traffic/log/bro/dump.log; \
	    > /home/traffic/log/bro/fail.log; \
	    > /home/traffic/log/bro/rate.log; \
	    rm -rf /home/traffic/log/bro/api; \
	    mkdir -p /home/traffic/log/bro/api; \
	    rm -rf /home/traffic/log/bro/tmp; \
	    mkdir -p /home/traffic/log/bro/tmp; \
	    for file in $$(ls /home/traffic/log/bro) ; do \
	        [ -d "/home/traffic/log/bro/$${file}" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "api" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "http" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "info" ] && \
	        [ "/home/traffic/log/bro/$${file}" != "tmp" ] && \
	        rm -rf "/home/traffic/log/bro/$${file}" || true; \
	    done \
	else \
	    rm -f ../logs/*.lock; \
	    > ../logs/dump.log; \
	    > ../logs/fail.log; \
	    > ../logs/rate.log; \
	    find ../logs \
	        ! -iname 'api' \
	        ! -iname 'http' \
	        ! -iname 'info' \
	        ! -iname 'tmp' -type d -depth 1 -print0 | xargs -0 rm -rf; \
	    find ../logs/api -depth 1 -print0 | xargs -0 rm -rf; \
	    find ../logs/tmp -iname '*.json' -depth 1 -type f -print0 | xargs -0 rm -rf; \
	fi

clean-api:
	rm -rf include/api/application/vnd.openxmlformats-officedocument/MaliciousMacroBot
	rm -rf include/api/application/x-executable/ELF-Parser/elfparser/
	rm -rf include/api/application/javascript/JaSt/JaSt
	rm -rf include/api/application/octet-stream/LMD/linux-malware-detect

mkdir-dump:
	mkdir -p ../dump

mkdir-logs:
	mkdir -p ../logs
