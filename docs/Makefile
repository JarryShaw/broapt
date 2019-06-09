MAN_PATH = ${MAN_PATH=/usr/local/share/man/}

man:
	rst2man.py broaptd.rst > broaptd.8

setup:
	cp broaptd.8 ${MAN_PATH}/man8
	[ -f ~/.bashrc ] && echo 'export MANPATH="/usr/local/share/man:$MANPATH"' >> ~/.bashrc
	[ -f ~/.bash_profile ] && echo 'export MANPATH="/usr/local/share/man:$MANPATH"' >> ~/.bash_profile
