#include <minix/ds.h>
#include <minix/fwdec.h>
#include <string.h>

#include "syslib.h"
#include <stdio.h>

/*
	* Sending IPC message to fwdec server
	* Returns a message with type LWIP_KEEP_PACKET or LWIP_DROP_PACKET
	*/
static int do_invoke_fwdec(message *m)
{
	int res = ipc_sendrec(FWDEC_PROC_NR,m);
	if (res != OK) {
	  return LWIP_DROP_PACKET;//If ipc fails we drop the packet for security reasons
	}

	switch (m->m_type) {
	  case LWIP_KEEP_PACKET:
	    return LWIP_KEEP_PACKET;
		case LWIP_DROP_PACKET:
		  return LWIP_DROP_PACKET;
		default:
			printf("lwip: warning, got illegal request from %d\n", m->m_source);
			return EINVAL;
	}
}

int fwdec_ip4_incoming(uint32_t src_ip, uint32_t dest_ip) {
	message m;
	memset(&m, 0, sizeof(m));

	m.m_type = FWDEC_QUERY_IP4_INC;
	m.m_fwdec_ip4.src_ip = src_ip;
	m.m_fwdec_ip4.dest_ip = dest_ip;

	return do_invoke_fwdec(&m);
}

int fwdec_ip4_outgoing(uint32_t src_ip, uint32_t dest_ip) {
	message m;
	memset(&m, 0, sizeof(m));

	m.m_type = FWDEC_QUERY_IP4_OUT;
	m.m_fwdec_ip4.src_ip = src_ip;
	m.m_fwdec_ip4.dest_ip = dest_ip;

	return do_invoke_fwdec(&m);
}

int fwdec_add_rule(uint32_t src_ip, uint32_t dest_ip, char* p_name, uint8_t action) {
	message m;
	memset(&m, 0, sizeof(m));

	m.m_type = FWDEC_ADD_RULE;
	m.m_fwdec_rule_message.src_ip = src_ip;
	m.m_fwdec_rule_message.dest_ip = dest_ip;
	strcpy(m.m_fwdec_rule_message.p_name,p_name);
	m.m_fwdec_rule_message.action = action;

	return do_invoke_fwdec(&m);
}
