.PHONY: docker f2format

docker:
	docker build --rm --tag bro .
	docker system prune --volumes -f

f2format:
	rm -rf source/python
	cp -rf source/python-dev source/python
	pipenv run f2format \
	    --no-archive \
	    --encoding='UTF-8' \
	    --python='3.7' source/python
