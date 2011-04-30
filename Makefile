include $(GOROOT)/src/Make.inc

TARG=steg
GOFILES=\
	main.go\
	aes.go\
	steg.go\

include $(GOROOT)/src/Make.cmd
