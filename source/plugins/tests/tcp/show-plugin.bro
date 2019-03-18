# @TEST-EXEC: bro -NN Reass::TCP |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
