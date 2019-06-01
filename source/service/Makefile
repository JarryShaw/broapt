setup:
	cp -f ../bin/broaptd.linux /usr/local/bin/broaptd
	cp -f broaptd.service /usr/lib/systemd/system/
	cp -f broaptd.env /etc/sysconfig/broaptd
	systemctl enable broaptd.service
	systemctl daemon-reload
	systemctl restart broaptd.service
