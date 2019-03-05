.PHONY: init clean

init: mkdir-contents mkdir-extract_files
clean: clean-contents clean-extract_files clean-logs clean-state

clean-contents:
	find contents -iname '*.dat' -print0 | xargs -0 rm -f

clean-extract_files:
	find extract_files -type df -depth 1 -print0 | xargs -0 rm -rf

clean-logs:
	rm -f *.log

clean-state:
	rm -rf .state

mkdir-contents:
	mkdir -p contents

mkdir-extract_files:
	mkdir -p extract_files
