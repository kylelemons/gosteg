.PHONY : all pkg cmd install clean nuke test bench

PKGS=steg
CMDS=gosteg

all : pkg cmd

pkg :
	@for PKG in $(PKGS); do $(MAKE) -C src/pkg/$${PKG} install; done

cmd : pkg
	@for CMD in $(CMDS); do $(MAKE) -C src/cmd/$${CMD}; done

test bench :
	@for PKG in $(PKGS); do $(MAKE) -C src/pkg/$${PKG} $@; done

install clean nuke :
	@for PKG in $(PKGS); do $(MAKE) -C src/pkg/$${PKG} $@; done
	@for CMD in $(CMDS); do $(MAKE) -C src/cmd/$${CMD} $@; done
	
