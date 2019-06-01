setup:
	cp ../bin/broaptd.linux /usr/local/bin/broaptd
	cp broaptd.service /usr/lib/systemd/system/
	cp broaptd.env /etc/sysconfig/broaptd
	systemctl enable broaptd.service
	systemctl daemon-reload
	systemctl restart broaptd.service
