.PHONY: init clean

init: mkdir-contents mkdir-extract_files
clean: clean-contents clean-logs clean-state

clean-contents:
	find contents -iname '*.dat' -print0 | xargs -0 rm -f

clean-logs:
	rm -f *.log

clean-state:
	rm -rf .state

mkdir-contents:
	mkdir -p contents

mkdir-extract_files:
	mkdir -p extract_files
