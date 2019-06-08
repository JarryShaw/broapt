.PHONY: bro broker

bro: bro-build docker-prune
broker: broker-build docker-prune

bro-build:
	docker build --rm \
	    -f Bro.dockerfile \
	    -t bro:2.6.1 -t bro:latest .

broker-build:
	docker build --rm \
	    -f Broker.dockerfile \
	    -t broker:1.1.2 -t broker:latest .

docker-prune:
	docker system prune --volumes -f
