#include <minix/ds.h>
#include <minix/fwtcp.h>
#include <string.h>

#include "syslib.h"

static int do_invoke_fwtcp(message *m, int type)
{
	int r;

	r = _taskcall(FWTCP_PROC_NR, type, m);

	return r;
}

int fwtcp_check_packet(uint32_t src_ip, uint64_t flags)
{
	message m;
	memset(&m, 0, sizeof(m));

	m.m_type = FWTCP_CHECK_PACKET;
	m.m_fwdec_ip4.src_ip = src_ip;
	m.m_fwdec_ip4.flags = flags;

	return do_invoke_fwtcp(&m, FWTCP_CHECK_PACKET);
}
