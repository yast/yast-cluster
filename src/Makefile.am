# Makefile.am for cluster/src

yncludedir = @yncludedir@/cluster

client_DATA =			\
	cluster.ycp		\
	cluster_auto.ycp	\
	cluster_proposal.ycp

ynclude_DATA =			\
	helps.ycp		\
	wizards.ycp		\
	dialogs.ycp		\
	common.ycp		\
	complex.ycp

desktop_DATA =			\
	cluster.desktop

module_DATA =			\
	Cluster.ycp

# create a symlink for local build, #145327
cluster:
	ln -sf . $@
ycpchook = cluster

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common
