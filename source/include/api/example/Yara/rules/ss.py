import os
PATH = os.path.dirname(os.path.realpath(__file__))
def recur(path):
	for f in os.listdir(path):
		filename = os.path.join(path, f)
		if os.path.isdir(filename):
			recur(filename)
		else:
			if filename.endswith("yara"):
				os.system(f"mv {filename} {filename[:-1]}")
				print(filename)

recur(PATH)
