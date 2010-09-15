mod_mvproc.la: mod_mvproc.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_mvproc.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_mvproc.la
