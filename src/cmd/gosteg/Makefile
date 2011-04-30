include $(GOROOT)/src/Make.inc

deppkg=kevlar/steg

TARG=gosteg
GOFILES=\
	main.go\

PREREQ+=$(foreach pkg,$(deppkg),$(GOROOT)/pkg/$(GOOS)_$(GOARCH)/$(pkg).a)

include $(GOROOT)/src/Make.cmd
