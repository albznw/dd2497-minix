#ifndef _FWTCP_PROTO_H
#define _FWTCP_PROTO_H

/* Function prototypes. */

/* main.c */
int main(int argc, char **argv);

/* fwtcp.c */
int do_check_packet(message *m_ptr);
int tcpSynProtection(uint32_t srcIp, uint8_t syn, uint8_t ack);
int sef_cb_init_fresh(int type, sef_init_info_t *info);

#endif
