#include "syslib.h"
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

int
getepname(endpoint_t proc_ep, char * buf, int buf_len)
{
	message m;
	int r;

	memset(&m, 0, sizeof(m));
	m.m_lsys_pm_getepname.endpt = proc_ep;

	if ((r = _taskcall(PM_PROC_NR, PM_GETEPNAME, &m)) < 0)
		return r;

	strncpy(buf, m.m_pm_lsys_getepname.proc_name, buf_len);

	return OK;
}

int
getepeffuid(endpoint_t proc_ep, uid_t * effuid)
{
	message m; /*m kommer fyllas med svaret*/
	int r;

	memset(&m, 0, sizeof(m));
	m.m_lsys_pm_getepname.endpt = proc_ep;

	if ((r = _taskcall(PM_PROC_NR, PM_GETEPEFFUID, &m)) < 0)
		return r;

	*effuid = m.m_pm_lsys_getepeffuid.eff_uid;

	return OK;
}

pid_t
getepinfo(endpoint_t proc_ep, uid_t *uid, gid_t *gid)
{
	message m;
	int r;

	memset(&m, 0, sizeof(m));
	m.m_lsys_pm_getepinfo.endpt = proc_ep;
	m.m_lsys_pm_getepinfo.groups = (vir_bytes)NULL;
	m.m_lsys_pm_getepinfo.ngroups = 0;

	if ((r = _taskcall(PM_PROC_NR, PM_GETEPINFO, &m)) < 0)
		return r;

	if (uid != NULL)
		*uid = m.m_pm_lsys_getepinfo.euid;
	if (gid != NULL)
		*gid = m.m_pm_lsys_getepinfo.egid;
	return (pid_t) r;
}

pid_t
getnpid(endpoint_t proc_ep)
{
	return getepinfo(proc_ep, NULL, NULL);
}

uid_t
getnuid(endpoint_t proc_ep)
{
	uid_t uid;
	int r;

	if ((r = getepinfo(proc_ep, &uid, NULL)) < 0)
		return (uid_t) r;

	return uid;
}

gid_t
getngid(endpoint_t proc_ep)
{
	gid_t gid;
	int r;

	if ((r = getepinfo(proc_ep, NULL, &gid)) < 0)
		return (gid_t) r;

	return gid;
}

int
getsockcred(endpoint_t proc_ep, struct sockcred * sockcred, gid_t * groups,
	int ngroups)
{
	message m;
	int r;

	memset(&m, 0, sizeof(m));
	m.m_lsys_pm_getepinfo.endpt = proc_ep;
	m.m_lsys_pm_getepinfo.groups = (vir_bytes)groups;
	m.m_lsys_pm_getepinfo.ngroups = ngroups;

	if ((r = _taskcall(PM_PROC_NR, PM_GETEPINFO, &m)) < 0)
		return r;

	sockcred->sc_uid = m.m_pm_lsys_getepinfo.uid;
	sockcred->sc_euid = m.m_pm_lsys_getepinfo.euid;
	sockcred->sc_gid = m.m_pm_lsys_getepinfo.gid;
	sockcred->sc_egid = m.m_pm_lsys_getepinfo.egid;
	sockcred->sc_ngroups = m.m_pm_lsys_getepinfo.ngroups;

	return OK;
}
