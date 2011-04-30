include $(GOROOT)/src/Make.inc

TARG=gosteg
GOFILES=\
	main.go\
	aes.go\
	gosteg.go\

include $(GOROOT)/src/Make.cmd
