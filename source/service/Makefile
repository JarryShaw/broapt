setup:
	cp broaptd.service /usr/lib/systemd/system/
	cp broaptd.env /etc/sysconfig/
	systemctl enable broaptd.service
	systemctl daemon-reload
	systemctl restart broaptd.service
