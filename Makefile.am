AM_CFLAGS = -Wall -Wextra -D_FORTIFY_SOURCE=2 $(PIE_CFLAGS) $(RELRO_CFLAGS)
ACLOCAL_AMFLAGS = -I aclocal

root_exec_sbindir = $(ROOTSBINDIR)
root_exec_sbin_PROGRAMS = mount.cifs
mount_cifs_SOURCES = mount.cifs.c mtab.c $(resolve_hosts_SOURCES) util.c
mount_cifs_LDADD = $(LIBCAP) $(CAPNG_LDADD) $(RT_LDADD) $(resolve_hosts_LDADD)
include_HEADERS = cifsidmap.h
rst_man_pages = mount.cifs.8

#
# Generate man pages troff source from POD format
#

man_MANS=

SUFFIXES = .rst .1 .8

RST2MAN = $(have_rst2man) --syntax-highlight=none $< $@

.rst.1:
	$(RST2MAN)
.rst.8:
	$(RST2MAN)

CLEANFILES =
bin_PROGRAMS =
bin_SCRIPTS =
sbin_PROGRAMS =

resolve_hosts_SOURCES = data_blob.c asn1.c cldap_ping.c resolve_host.c
resolve_hosts_LDADD = -ltalloc -lresolv

if CONFIG_CIFSUPCALL
sbin_PROGRAMS += cifs.upcall
cifs_upcall_SOURCES = cifs.upcall.c data_blob.c asn1.c spnego.c
cifs_upcall_LDADD = -ltalloc -lkeyutils $(GSSAPI_LDADD) $(KRB5_LDADD) $(CAPNG_LDADD)
rst_man_pages += cifs.upcall.8
#
# Fix the pathnames in manpages. To prevent @label@ being replaced by m4, we
# need to obfuscate the LHS of the regex (hence the trivial one character set).
#
cifs.upcall.rst: cifs.upcall.rst.in
	$(SED) 's,[@]sbindir@,$(sbindir),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_CIFSCREDS
bin_PROGRAMS += cifscreds
cifscreds_SOURCES = cifscreds.c cifskey.c $(resolve_hosts_SOURCES) util.c
cifscreds_LDADD = -lkeyutils $(resolve_hosts_LDADD)

rst_man_pages += cifscreds.1

endif

if CONFIG_CIFSIDMAP
sbin_PROGRAMS += cifs.idmap
cifs_idmap_SOURCES = cifs.idmap.c idmap_plugin.c
cifs_idmap_LDADD = -lkeyutils -ldl
rst_man_pages += cifs.idmap.8
CLEANFILES += cifs.idmap.rst
cifs.idmap.rst: cifs.idmap.rst.in
	$(SED) -e 's,[@]sbindir@,$(sbindir),' -e 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_CIFSACL
bin_PROGRAMS += getcifsacl
getcifsacl_SOURCES = getcifsacl.c idmap_plugin.c
getcifsacl_LDADD = -ldl

rst_man_pages += getcifsacl.1
CLEANFILES += getcifsacl.rst
getcifsacl.rst: getcifsacl.rst.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@

bin_PROGRAMS += setcifsacl
setcifsacl_SOURCES = setcifsacl.c idmap_plugin.c
setcifsacl_LDADD = -ldl

rst_man_pages += setcifsacl.1
CLEANFILES += setcifsacl.rst
setcifsacl.rst: setcifsacl.rst.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_SMBINFO
bin_SCRIPTS += smbinfo
rst_man_pages += smbinfo.1
endif

if CONFIG_PYTHON_TOOLS
bin_SCRIPTS += smb2-quota
rst_man_pages += smb2-quota.1
endif

if CONFIG_PLUGIN
plugindir = $(pkglibdir)
plugin_PROGRAMS = idmapwb.so
idmapwb.so: idmapwb.c
	$(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) $(WBCLIENT_CFLAGS) $(LDFLAGS) -shared -fpic -o $@ $+ $(WBCLIENT_LIBS)

rst_man_pages += idmapwb.8
CLEANFILES += idmapwb.rst
idmapwb.rst: idmapwb.rst.in
	$(SED) 's,[@]pluginpath@,$(pluginpath),' $(srcdir)/$@.in > $@-t && mv $@-t $@
endif

if CONFIG_PAM
pam_PROGRAMS = pam_cifscreds.so
rst_man_pages += pam_cifscreds.8
pam_cifscreds.so: pam_cifscreds.c cifskey.c $(resolve_hosts_SOURCES) util.c
	$(CC) $(DEFS) $(CFLAGS) $(AM_CFLAGS) $(LDFLAGS) -shared -fpic -o $@ $+ -lpam -lkeyutils $(resolve_hosts_LDADD)

endif

if CONFIG_MAN
man_MANS += $(rst_man_pages)
CLEANFILES += $(rst_man_pages)
endif

SUBDIRS = contrib

install-exec-hook: install-sbinPROGRAMS
	(cd $(DESTDIR)$(ROOTSBINDIR) && ln -sf mount.cifs mount.smb3)

install-data-hook:
if CONFIG_MAN
	( cd $(DESTDIR)$(man8dir) && ln -sf mount.cifs.8 mount.smb3.8)
endif

uninstall-hook:
	(cd $(DESTDIR)$(ROOTSBINDIR) && rm -f $(ROOTSBINDIR)/mount.smb3)
	(cd $(DESTDIR)$(man8dir) && rm -f $(DESTDIR)$(man8dir)/mount.smb3.8)
