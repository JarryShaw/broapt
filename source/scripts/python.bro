global pong: event(n: int);

event ping(n: int) {
	event pong(n);
}

event bro_init() {
	Broker::subscribe("/tmp/test");
	Broker::listen("127.0.0.1", 9999/tcp);
	Broker::auto_publish("/tmp/test", pong);
}
