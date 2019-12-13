#include "inc.h"	/* include master header file */
#include <minix/endpoint.h>
#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

/* Allocate space for the global variables. */
static endpoint_t who_e;	/* caller's proc number */
static int callnr;		/* system call number */

/* Message parameters */
static char proc_name[16];
static uint32_t src_ip;
static uint32_t dest_ip;
static uint16_t src_port;
static uint16_t dest_port;
static uint64_t flags;

/* Declare local functions. */
static void get_work(message *m_ptr);
static void reply(endpoint_t whom, message *m_ptr);

/* SEF functions and variables. */
static void sef_local_startup(void);

/*===========================================================================*
 *				main                                         *
 *===========================================================================*/
int main(int argc, char **argv)
{
/* This is the main routine of this service. The main loop consists of 
 * three major activities: getting new work, processing the work, and
 * sending the reply. The loop never terminates, unless a panic occurs.
 */
  
  message m;
  int result;                 

  /* SEF local startup. */
  env_setargs(argc, argv);
  sef_local_startup();

  /* Main loop - get work and do it, forever. */         
  while (TRUE) {              

      /* Wait for incoming message, sets 'callnr' and 'who'. */
      get_work(&m);

      if (is_notify(callnr)) {
          printf("fwdec: warning, got illegal notify from: %d\n", m.m_source);
          result = EINVAL;
          goto send_reply;
      }

      /* TODO remove SHIT this since its only needed for the DEMO */
      unsigned char src_bytes[4];
      src_bytes[0] = src_ip & 0xFF;
      src_bytes[1] = (src_ip >> 8) & 0xFF;
      src_bytes[2] = (src_ip >> 16) & 0xFF;
      src_bytes[3] = (src_ip >> 24) & 0xFF;

      unsigned char dest_bytes[4];
      dest_bytes[0] = dest_ip & 0xFF;
      dest_bytes[1] = (dest_ip >> 8) & 0xFF;
      dest_bytes[2] = (dest_ip >> 16) & 0xFF;
      dest_bytes[3] = (dest_ip >> 24) & 0xFF;

      switch (callnr) {
      case FWDEC_QUERY_IP4_INC:
          result = check_incoming_ip4(src_ip);
          break;
      case FWDEC_QUERY_IP4_OUT:
          result = check_outgoing_ip4(dest_ip, NULL);
          break;
      case FWDEC_QUERY_TCP_INC:
          // TODO add TCP functions and logic
          result = check_incoming_ip4(dest_ip);
          printf("TCP IN %d.%d.%d.%d:%d <- %d.%d.%d.%d:%d (%s) %s\n", dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], dest_port, src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], src_port, proc_name, (result == LWIP_DROP_PACKET ? "BLOCKED" : "ALLOWED"));
          break;
      case FWDEC_QUERY_TCP_OUT:
          // TODO add TCP functions and logic
          result = check_outgoing_ip4(dest_ip, proc_name);
          printf("TCP OUT %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (%s) %s\n", src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], src_port, dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], dest_port, proc_name, (result == LWIP_DROP_PACKET ? "BLOCKED" : "ALLOWED"));
          break;
      case FWDEC_QUERY_UDP_INC:
          // TODO add UDP functions and logic
          if(strcmp(proc_name, "dig") == 0) {
            result = LWIP_DROP_PACKET;
          } else {
            result = check_incoming_ip4(dest_ip);
          }
          printf("UDP IN %d.%d.%d.%d:%d <- %d.%d.%d.%d:%d (%s) %s\n", dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], dest_port, src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], src_port, proc_name, (result == LWIP_DROP_PACKET ? "BLOCKED" : "ALLOWED"));
          break;
      case FWDEC_QUERY_UDP_OUT:
          // TODO add UDP functions and logic
          if(strcmp(proc_name, "dig") == 0) {
            result = LWIP_DROP_PACKET;
          } else {
            result = check_outgoing_ip4(dest_ip, proc_name);
          }
          printf("UDP OUT %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (%s) %s\n", src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], src_port, dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], dest_port, proc_name, (result == LWIP_DROP_PACKET ? "BLOCKED" : "ALLOWED"));
          break;
      case FWDEC_QUERY_RAW_INC:
          // TODO add RAW functions and logic
          result = check_incoming_ip4(dest_ip);
          printf("RAW IN %d.%d.%d.%d <- %d.%d.%d.%d (%s) %s\n", dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], proc_name, (result == LWIP_DROP_PACKET ? "BLOCKED" : "ALLOWED"));
          break;
      case FWDEC_QUERY_RAW_OUT:
          // TODO add RAW functions and logic
          result = check_outgoing_ip4(dest_ip, proc_name);
          printf("RAW OUT %d.%d.%d.%d -> %d.%d.%d.%d (%s) %s\n", src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], proc_name, (result == LWIP_DROP_PACKET ?  "BLOCKED" : "ALLOWED"));
          break;
      case FWDEC_QUERY_ICMP_INC:
          // TODO add ICMP functions and logic
          result = check_incoming_ip4(dest_ip);
          printf("ICMP IN %d.%d.%d.%d <- %d.%d.%d.%d %s\n", dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], (result == LWIP_DROP_PACKET ? "BLOCKED" : "ALLOWED"));
          break;
      case FWDEC_QUERY_ICMP_OUT:
          // TODO add ICMP functions and logic
          result = check_outgoing_ip4(dest_ip, NULL);
          printf("ICMP OUT %d.%d.%d.%d -> %d.%d.%d.%d %s\n", src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3], dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3], (result == LWIP_DROP_PACKET ? "BLOCKED" : "ALLOWED"));
          break;
      default: 
          printf("fwdec: warning, got illegal request from %d\n", m.m_source);
          result = EINVAL;
      }

send_reply:
      memset(&m,0, sizeof(m));
      /* Finally send reply message, unless disabled. */
      if (result != EDONTREPLY) {
          m.m_type = result;  		/* build reply message */
          reply(who_e, &m);		/* send it away */
      }
  }
  return(OK);				/* shouldn't come here */
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void sef_local_startup()
{
  /* Register init callbacks. */
  sef_setcb_init_fresh(sef_cb_init_fresh);
  sef_setcb_init_restart(sef_cb_init_fresh);

  /* Let SEF perform startup. */
  sef_startup();
}

/*===========================================================================*
 *				get_work                                     *
 *===========================================================================*/
static void get_work(
  message *m_ptr			/* message buffer */
)
{
    int status = sef_receive(ANY, m_ptr);   /* blocks until message arrives */
    if (OK != status)
        panic("failed to receive message!: %d", status);
    who_e = m_ptr->m_source;        /* message arrived! set sender */
    callnr = m_ptr->m_type;       /* set function call number */
    if(m_ptr->m_fwdec_ip4.user_endp) {
        getepname(m_ptr->m_fwdec_ip4.user_endp, proc_name, 16);
    }
    src_ip = m_ptr->m_fwdec_ip4.src_ip;
    dest_ip = m_ptr->m_fwdec_ip4.dest_ip;
    src_port = m_ptr->m_fwdec_ip4.src_port;
    dest_port = m_ptr->m_fwdec_ip4.dest_port;
    flags = m_ptr->m_fwdec_ip4.flags;
}

/*===========================================================================*
 *				reply					     *
 *===========================================================================*/
static void reply(
  endpoint_t who_e,			/* destination */
  message *m_ptr			/* message buffer */
)
{
    int s = ipc_send(who_e, m_ptr);    /* send the message */
    if (OK != s)
        printf("fwdec: unable to send reply to %d: %d\n", who_e, s);
}
