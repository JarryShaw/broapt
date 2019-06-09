.PHONY: all

all: andropytool bro-phishing elfparser jast maliciousmacrobot smtp-url-analysis

ROOT := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))

andropytool:
	git submodule add https://github.com/alexMyG/AndroPyTool.git $(ROOT)/AndroPyTool

bro-phishing:
	git submodule add https://github.com/hosom/bro-phishing.git $(ROOT)/bro-phishing

elfparser:
	git submodule add https://github.com/jacob-baines/elfparser.git $(ROOT)/elfparser

jast:
	git submodule add https://github.com/Aurore54F/JaSt.git $(ROOT)/JaSt

maliciousmacrobot:
	git submodule add https://github.com/egaus/MaliciousMacroBot.git $(ROOT)/MaliciousMacroBot

smtp-url-analysis:
	git submodule add https://github.com/initconf/smtp-url-analysis.git $(ROOT)/smtp-url-analysis
