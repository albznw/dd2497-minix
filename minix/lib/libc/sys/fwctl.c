#include <lib.h>
#include <stdio.h>
#include <string.h>
#include <sys/svrctl.h>

int fwdec_add_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
						uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name) {
	message m;
	memset(&m, 0, sizeof(m));

	m.m_fwdec_rule.method = FWDEC_ADD_RULE;
	m.m_fwdec_rule.direction = direction;
	m.m_fwdec_rule.type = type;
	m.m_fwdec_rule.priority = priority;
	m.m_fwdec_rule.action = action;
	m.m_fwdec_rule.ip_start = ip_start;
	m.m_fwdec_rule.ip_end = ip_end;
	m.m_fwdec_rule.port = port;
	strncpy(m.m_fwdec_rule.p_name, p_name, 16);

	return _syscall(VFS_PROC_NR, VFS_FWCTL, &m);
}

int fwdec_delete_rule(uint8_t direction, uint8_t type, uint8_t priority, uint8_t action,
						uint32_t ip_start, uint32_t ip_end, uint16_t port, char* p_name) {
	message m;
	memset(&m, 0, sizeof(m));

	m.m_fwdec_rule.method = FWDEC_DEL_RULE;
	m.m_fwdec_rule.direction = direction;
	m.m_fwdec_rule.type = type;
	m.m_fwdec_rule.priority = priority;
	m.m_fwdec_rule.action = action;
	m.m_fwdec_rule.ip_start = ip_start;
	m.m_fwdec_rule.ip_end = ip_end;
	m.m_fwdec_rule.port = port;
	strncpy(m.m_fwdec_rule.p_name, p_name, 16);

	return _syscall(VFS_PROC_NR, VFS_FWCTL, &m);
}

int fwdec_list_rules(void) {
	message m;
	memset(&m, 0, sizeof(m));
	m.m_fwdec_rule.method = FWDEC_LIST_RULES;
	return _syscall(VFS_PROC_NR, VFS_FWCTL, &m);
}
