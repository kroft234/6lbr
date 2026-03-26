/*
 * Copyright (c) 2004, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *         Code for tunnelling uIP packets over the Rime mesh routing module
 *
 * \author  Adam Dunkels <adam@sics.se>\author
 * \author  Mathilde Durvy <mdurvy@cisco.com> (IPv6 related code)
 * \author  Julien Abeille <jabeille@cisco.com> (IPv6 related code)
 */

#include "contiki-net.h"
#include "net/ip/uip-split.h"
#include "net/ip/uip-packetqueue.h"
#include "net/rpl/rpl-private.h"

#if NETSTACK_CONF_WITH_IPV6
#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-ds6.h"
#endif

#if CETIC_6LBR
#include "cetic-6lbr.h"
#endif
#if CETIC_6LBR_IP64
#include "ip64.h"
#include "net/ip/ip64-addr.h"
#endif

#include <string.h>

#define DEBUG DEBUG_PRINT
/*#define DEBUG DEBUG_NONE*/
#include "net/ip/uip-debug.h"

#if UIP_LOGGING
#include <stdio.h>
void uip_log(char *msg);
#define UIP_LOG(m) uip_log(m)
#else
#define UIP_LOG(m)
#endif

#define UIP_ICMP_BUF ((struct uip_icmp_hdr *)&uip_buf[UIP_LLIPH_LEN + uip_ext_len])
#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_TCP_BUF ((struct uip_tcpip_hdr *)&uip_buf[UIP_LLH_LEN])

#ifdef UIP_FALLBACK_INTERFACE
extern struct uip_fallback_interface UIP_FALLBACK_INTERFACE;
#endif

#if UIP_CONF_IPV6_RPL
#include "rpl/rpl.h"
#endif

process_event_t tcpip_event;
#if UIP_CONF_ICMP6
process_event_t tcpip_icmp6_event;
#endif /* UIP_CONF_ICMP6 */

/* Periodic check of active connections. */
static struct etimer periodic;

#if NETSTACK_CONF_WITH_IPV6 && UIP_CONF_IPV6_REASSEMBLY
/* Timer for reassembly. */
extern struct etimer uip_reass_timer;
#endif

#if UIP_TCP
/**
 * \internal Structure for holding a TCP port and a process ID.
 */
struct listenport {
  uint16_t port;
  struct process *p;
};

static struct internal_state {
  struct listenport listenports[UIP_LISTENPORTS];
  struct process *p;
} s;
#endif

enum {
  TCP_POLL,
  UDP_POLL,
  PACKET_INPUT
};

/*------------------------------------------------------------1*/
#define SSH_PORT 22
#define NAT_TABLE_SIZE 8

struct nat_entry {
    uip_ip6addr_t orig_src;   // IP Orangepi
    uint16_t orig_src_port;   // порт Orangepi
    uip_ip6addr_t new_dst;    // IP Linux (bbbb::)
    uint16_t new_dst_port;    // порт Linux (22)
    uint8_t valid;
};

static struct nat_entry nat_table[NAT_TABLE_SIZE];
/*------------------------------------------------------------1*/

/*-------------------------Добавленные-----------------------------------*/
static void print_ip6(const char *label, const uip_ip6addr_t *addr)
{
  int i;
  printf("%s ", label);
  for(i = 0; i < 8; i++) {
    printf("%04x", uip_ntohs(addr->u16[i]));
    if(i < 7) printf(":");
  }
  printf("\n");
}

static void print_tcp_flags(uint8_t flags)
{
  printf("TCP flags: ");

  if(flags & 0x02) printf("SYN ");
  if(flags & 0x10) printf("ACK ");
  if(flags & 0x01) printf("FIN ");
  if(flags & 0x04) printf("RST ");
  if(flags & 0x08) printf("PSH ");
  if(flags & 0x20) printf("URG ");

  printf("\n");
}/*-------------------------Добавленные-----------------------------------*/

/* Called on IP packet output. */
#if NETSTACK_CONF_WITH_IPV6

static uint8_t (* outputfunc)(const uip_lladdr_t *a);

uint8_t
tcpip_output(const uip_lladdr_t *a)
{
  int ret;
  if(outputfunc != NULL) {
    ret = outputfunc(a);
    return ret;
  }
  UIP_LOG("tcpip_output: Use tcpip_set_outputfunc() to set an output function");
  return 0;
}

void
tcpip_set_outputfunc(uint8_t (*f)(const uip_lladdr_t *))
{
  outputfunc = f;
}

outputfunc_t
tcpip_get_outputfunc(void)
{
  return outputfunc;
}

#else

static uint8_t (* outputfunc)(void);
uint8_t
tcpip_output(void)
{
  if(outputfunc != NULL) {
    return outputfunc();
  }
  UIP_LOG("tcpip_output: Use tcpip_set_outputfunc() to set an output function");
  return 0;
}

void
tcpip_set_outputfunc(uint8_t (*f)(void))
{
  outputfunc = f;
}
#endif

static inputfunc_t inputfunc;

/*void
tcpip_input(void)
{
  printf("\n>>> tcpip_input() CALLED  uip_len = %d <<<\n", uip_len);
  if(inputfunc != NULL) {
    printf("  > calling inputfunc() now\n");
    inputfunc();
  }
  UIP_LOG("tcpip_input: Use tcpip_set_inputfunc() to set an input function");
}*/

void
tcpip_input(void)
{
  printf("\n>>> tcpip_input() CALLED  uip_len = %d <<<\n", uip_len);

  if (uip_len == 0) {
    printf("  empty packet > return\n");
    return;
  }

  if (UIP_IP_BUF->proto == UIP_PROTO_TCP) {
    printf("  PROTO=TCP !  dport = %u   sport = %u   flags = 0x%02x\n",
           uip_ntohs(UIP_TCP_BUF->destport),
           uip_ntohs(UIP_TCP_BUF->srcport),
           UIP_TCP_BUF->flags);
    if (uip_ntohs(UIP_TCP_BUF->destport) == 22) {
      printf("  !!! SSH PORT 22 DETECTED IN tcpip_input !!!\n");
    }
  } else if (UIP_IP_BUF->proto == UIP_PROTO_ICMP6) {
    printf("  PROTO=ICMPv6  type = %d\n", UIP_ICMP_BUF->type);
  } else {
    printf("  PROTO = %d (не TCP и не ICMPv6)\n", UIP_IP_BUF->proto);
  }

  printf("  src = "); PRINT6ADDR(&UIP_IP_BUF->srcipaddr); printf("\n");
  printf("  dst = "); PRINT6ADDR(&UIP_IP_BUF->destipaddr); printf("\n");

  if (inputfunc != NULL) {
    printf("  > calling inputfunc() now\n");
    inputfunc();
  } else {
    printf("  !!! inputfunc == NULL !!!  PACKET DROPPED HERE !!!\n");
  }

  // Если хочешь — можно оставить оригинальный UIP_LOG
  UIP_LOG("tcpip_input: Use tcpip_set_inputfunc() to set an input function");
}

void
tcpip_set_inputfunc(inputfunc_t f)
{
  inputfunc = f;
}

inputfunc_t
tcpip_get_inputfunc(void)
{
  return inputfunc;
}

#if UIP_CONF_IP_FORWARD
unsigned char tcpip_is_forwarding; /* Forwarding right now? */
#endif /* UIP_CONF_IP_FORWARD */

PROCESS(tcpip_process, "TCP/IP stack");

/*---------------------------------------------------------------------------*/
static void
start_periodic_tcp_timer(void)
{
  if(etimer_expired(&periodic)) {
    etimer_restart(&periodic);
  }
}
/*---------------------------------------------------------------------------*/
/* FORWARD NAT: любой TCP-пакет на порт 22 > переписываем dst aaaa:: > bbbb:: */
void check_for_tcp_syn(void)
{
  if (UIP_IP_BUF->proto != UIP_PROTO_TCP) {
    return;
  }

  uint16_t dst_port = uip_ntohs(UIP_TCP_BUF->destport);
  if (dst_port != SSH_PORT) {
    return;
  }

  printf("\n>>> FORWARD NAT SSH <<<\n");
  print_ip6("SRC:", &UIP_IP_BUF->srcipaddr);
  print_ip6("DST before:", &UIP_IP_BUF->destipaddr);
  printf("srcport=%u dstport=%u flags=0x%02x\n",
         uip_ntohs(UIP_TCP_BUF->srcport), dst_port, UIP_TCP_BUF->flags);

  // --- NAT TABLE ---
  struct nat_entry *e = NULL;
  for (int i = 0; i < NAT_TABLE_SIZE; i++) {
    if (!nat_table[i].valid) {
      e = &nat_table[i];
      break;
    }
  }
  if (!e) {
    printf("NAT table full > overwrite slot 0\n");
    e = &nat_table[0];
  }

  // сохраняем оригинальный src (для reverse NAT)
  uip_ip6addr_copy(&e->orig_src, &UIP_IP_BUF->srcipaddr);
  e->orig_src_port = uip_ntohs(UIP_TCP_BUF->srcport);
  e->new_dst_port = SSH_PORT;
  e->valid = 1;

  // --- НОВЫЙ DST = aaaa::1 ---
  uip_ip6addr(&e->new_dst, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);

  // переписываем пакет
  uip_ip6addr_copy(&UIP_IP_BUF->destipaddr, &e->new_dst);
  UIP_TCP_BUF->destport = uip_htons(SSH_PORT);

  // пересчёт checksum
  UIP_TCP_BUF->tcpchksum = 0;
  uint16_t new_sum = uip_tcpchksum();
  UIP_TCP_BUF->tcpchksum = ~new_sum;

  printf("Rewritten > DST: ");
  print_ip6("", &UIP_IP_BUF->destipaddr);
  printf("TCP checksum after: 0x%04x\n",
         uip_ntohs(UIP_TCP_BUF->tcpchksum));

  // ВАЖНО: ничего больше не делаем!
  // НЕ вызываем slip_send()
  // НЕ обнуляем uip_len
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/* REVERSE NAT: любой ответный TCP-пакет от сервера > переписываем src bbbb:: > aaaa:: */
void check_nat_reverse(void)
{
  if (UIP_IP_BUF->proto != UIP_PROTO_TCP) {
    return;
  }

  uint16_t src_port = uip_ntohs(UIP_TCP_BUF->srcport);
  uint16_t dst_port = uip_ntohs(UIP_TCP_BUF->destport);

  printf("\n=== REVERSE NAT CHECK ===\n");
  print_ip6("SRC:", &UIP_IP_BUF->srcipaddr);
  print_ip6("DST:", &UIP_IP_BUF->destipaddr);
  printf("srcport=%u dstport=%u flags=0x%02x\n", src_port, dst_port, UIP_TCP_BUF->flags);

  for (int i = 0; i < NAT_TABLE_SIZE; i++) {
    if (!nat_table[i].valid) continue;

    // Матчим по: src == сохранённый сервер (new_dst) И dst_port == оригинальный клиентский порт
    if (uip_ip6addr_cmp(&UIP_IP_BUF->srcipaddr, &nat_table[i].new_dst) &&
        dst_port == nat_table[i].orig_src_port) {

      printf(">>> REVERSE NAT MATCH slot %d <<<\n", i);
      print_ip6("Restoring src to original client: ", &nat_table[i].orig_src);

      // Переписываем src > оригинальный клиент (OrangePi)
      uip_ip6addr_copy(&UIP_IP_BUF->srcipaddr, &nat_table[i].orig_src);

      // srcport > оригинальный клиентский порт (не 22!)
      UIP_TCP_BUF->srcport = uip_htons(nat_table[i].orig_src_port);

      // Пересчитываем TCP-чек-сумму
      UIP_TCP_BUF->tcpchksum = 0;
      uint16_t sum = uip_tcpchksum();
      UIP_TCP_BUF->tcpchksum = ~sum;

      printf("Reverse rewrite done > SRC: ");
      print_ip6("", &UIP_IP_BUF->srcipaddr);
      printf("srcport now: %u\n", uip_ntohs(UIP_TCP_BUF->srcport));
      return;
    }
  }
  printf("No match in reverse NAT table\n");
}
/*---------------------------------------------------------------------------*/
static void
packet_input(void)
{
/*printf("\n*** PACKET_INPUT CALLED *** uip_len=%d\n", uip_len);

  if(uip_len > 0) {
    int proto = UIP_IP_BUF->proto;
    printf("proto = %d (", proto);
    if(proto == UIP_PROTO_TCP) {
     printf("TCP");
    }
    else if(proto == UIP_PROTO_ICMP6){
      printf("ICMPv6");
    }
    else if(proto == 17) {
      printf("UDP");
    }
    else {
     printf("other");
    }
    printf(")\n");

    if(proto == UIP_PROTO_TCP) {
      uint16_t dport = uip_ntohs(UIP_TCP_BUF->destport);
      uint16_t sport = uip_ntohs(UIP_TCP_BUF->srcport);
      uint8_t flags = UIP_TCP_BUF->flags;
      printf("TCP: sport=%u dport=%u flags=0x%02x\n", sport, dport, flags);
      if(dport == 22) {
        printf("!!! SSH TCP PACKET IN packet_input !!!\n");
        print_ip6("src: ", &UIP_IP_BUF->srcipaddr);
        print_ip6("dst: ", &UIP_IP_BUF->destipaddr);
      }
    } else if(proto == UIP_PROTO_ICMP6) {
      printf("ICMPv6 type = %d\n", UIP_ICMP_BUF->type);
    }
  }*/

#if UIP_CONF_IP_FORWARD

  PRINTF("\n=============================\n");
  PRINTF("=== PACKET_INPUT START ===\n");
  PRINTF("uip_len = %u\n", uip_len);

  if(uip_len > 0) {

    PRINTF("Next header (proto) = %u\n", UIP_IP_BUF->proto);
    PRINTF("SRC: "); PRINT6ADDR(&UIP_IP_BUF->srcipaddr); PRINTF("\n");
    PRINTF("DST: "); PRINT6ADDR(&UIP_IP_BUF->destipaddr); PRINTF("\n");

    if(UIP_IP_BUF->proto == UIP_PROTO_TCP) {
      PRINTF("TCP SRC port = %u\n", uip_ntohs(UIP_TCP_BUF->srcport));
      PRINTF("TCP DST port = %u\n", uip_ntohs(UIP_TCP_BUF->destport));
      PRINTF("TCP flags = 0x%02x\n", UIP_TCP_BUF->flags);
      PRINTF("TCP checksum = 0x%04x\n",
             uip_ntohs(UIP_TCP_BUF->tcpchksum));
    }

    tcpip_is_forwarding = 1;

    uint8_t fw_result = uip_fw_forward();
    PRINTF("uip_fw_forward() result = %u\n", fw_result);

    if(fw_result == UIP_FW_LOCAL) {

      PRINTF("Packet is LOCAL\n");

      tcpip_is_forwarding = 0;

      PRINTF("--- BEFORE NAT ---\n");
      PRINTF("DST before: "); PRINT6ADDR(&UIP_IP_BUF->destipaddr); PRINTF("\n");

      check_for_tcp_syn();
      check_nat_reverse();
      PRINTF("--- AFTER NAT ---\n");
      PRINTF("DST after: "); PRINT6ADDR(&UIP_IP_BUF->destipaddr); PRINTF("\n");

      PRINTF("Calling uip_input()\n");
      uip_input();

      PRINTF("After uip_input(), uip_len = %u\n", uip_len);

      if(uip_len > 0) {

#if UIP_CONF_TCP_SPLIT
        PRINTF("uip_split_output()\n");
        uip_split_output();
#else

#if NETSTACK_CONF_WITH_IPV6
        PRINTF("tcpip_ipv6_output()\n");
        tcpip_ipv6_output();
#else
        PRINTF("tcpip_output(), len=%d\n", uip_len);
        tcpip_output();
#endif

#endif
      }
    }

    tcpip_is_forwarding = 0;
  }

#else

  if(uip_len > 0) {

    /*PRINTF("\n=== PACKET_INPUT (NO FORWARD) ===\n");
    PRINTF("uip_len = %u\n", uip_len);
    PRINTF("proto = %u\n", UIP_IP_BUF->proto);

    if(UIP_IP_BUF->proto == UIP_PROTO_TCP) {
      PRINTF("TCP DST port = %u\n",
             uip_ntohs(UIP_TCP_BUF->destport));
      PRINTF("TCP flags = 0x%02x\n",
             UIP_TCP_BUF->flags);
    }*/

    check_for_tcp_syn();
    check_nat_reverse();
    /*PRINTF("Calling uip_input()\n");*/
    uip_input();

    /*PRINTF("After uip_input(), uip_len=%u\n", uip_len);*/

    if(uip_len > 0) {

#if UIP_CONF_TCP_SPLIT
      uip_split_output();
#else
#if NETSTACK_CONF_WITH_IPV6
      tcpip_ipv6_output();
#else
      tcpip_output();
#endif
#endif
    }
  }

#endif

  /*PRINTF("=== PACKET_INPUT END ===\n");*/
}
/*---------------------------------------------------------------------------*/
#if UIP_TCP
#if UIP_ACTIVE_OPEN
struct uip_conn *
tcp_connect(const uip_ipaddr_t *ripaddr, uint16_t port, void *appstate)
{
  struct uip_conn *c;
  
  c = uip_connect(ripaddr, port);
  if(c == NULL) {
    return NULL;
  }

  c->appstate.p = PROCESS_CURRENT();
  c->appstate.state = appstate;
  
  tcpip_poll_tcp(c);
  
  return c;
}
#endif /* UIP_ACTIVE_OPEN */
/*---------------------------------------------------------------------------*/
void
tcp_unlisten(uint16_t port)
{
  static unsigned char i;
  struct listenport *l;

  l = s.listenports;
  for(i = 0; i < UIP_LISTENPORTS; ++i) {
    if(l->port == port &&
       l->p == PROCESS_CURRENT()) {
      l->port = 0;
      uip_unlisten(port);
      break;
    }
    ++l;
  }
}
/*---------------------------------------------------------------------------*/
void
tcp_listen(uint16_t port)
{
  static unsigned char i;
  struct listenport *l;

  l = s.listenports;
  for(i = 0; i < UIP_LISTENPORTS; ++i) {
    if(l->port == 0) {
      l->port = port;
      l->p = PROCESS_CURRENT();
      uip_listen(port);
      break;
    }
    ++l;
  }
}
/*---------------------------------------------------------------------------*/
void
tcp_attach(struct uip_conn *conn,
	   void *appstate)
{
  uip_tcp_appstate_t *s;

  s = &conn->appstate;
  s->p = PROCESS_CURRENT();
  s->state = appstate;
}

#endif /* UIP_TCP */
/*---------------------------------------------------------------------------*/
#if UIP_UDP
void
udp_attach(struct uip_udp_conn *conn,
	   void *appstate)
{
  uip_udp_appstate_t *s;

  s = &conn->appstate;
  s->p = PROCESS_CURRENT();
  s->state = appstate;
}
/*---------------------------------------------------------------------------*/
struct uip_udp_conn *
udp_new(const uip_ipaddr_t *ripaddr, uint16_t port, void *appstate)
{
  struct uip_udp_conn *c;
  uip_udp_appstate_t *s;
  
  c = uip_udp_new(ripaddr, port);
  if(c == NULL) {
    return NULL;
  }

  s = &c->appstate;
  s->p = PROCESS_CURRENT();
  s->state = appstate;

  return c;
}
/*---------------------------------------------------------------------------*/
struct uip_udp_conn *
udp_broadcast_new(uint16_t port, void *appstate)
{
  uip_ipaddr_t addr;
  struct uip_udp_conn *conn;

#if NETSTACK_CONF_WITH_IPV6
  uip_create_linklocal_allnodes_mcast(&addr);
#else
  uip_ipaddr(&addr, 255,255,255,255);
#endif /* NETSTACK_CONF_WITH_IPV6 */
  conn = udp_new(&addr, port, appstate);
  if(conn != NULL) {
    udp_bind(conn, port);
  }
  return conn;
}
#endif /* UIP_UDP */
/*---------------------------------------------------------------------------*/
#if UIP_CONF_ICMP6
uint8_t
icmp6_new(void *appstate) {
  if(uip_icmp6_conns.appstate.p == PROCESS_NONE) {
    uip_icmp6_conns.appstate.p = PROCESS_CURRENT();
    uip_icmp6_conns.appstate.state = appstate;
    return 0;
  }
  return 1;
}

void
tcpip_icmp6_call(uint8_t type)
{
  if(uip_icmp6_conns.appstate.p != PROCESS_NONE) {
    /* XXX: This is a hack that needs to be updated. Passing a pointer (&type)
       like this only works with process_post_synch. */
    process_post_synch(uip_icmp6_conns.appstate.p, tcpip_icmp6_event, &type);
  }
  return;
}
#endif /* UIP_CONF_ICMP6 */
/*---------------------------------------------------------------------------*/
static void
eventhandler(process_event_t ev, process_data_t data)
{
#if UIP_TCP
  static unsigned char i;
  register struct listenport *l;
#endif /*UIP_TCP*/
  struct process *p;

  switch(ev) {
    case PROCESS_EVENT_EXITED:
      /* This is the event we get if a process has exited. We go through
         the TCP/IP tables to see if this process had any open
         connections or listening TCP ports. If so, we'll close those
         connections. */

      p = (struct process *)data;
#if UIP_TCP
      l = s.listenports;
      for(i = 0; i < UIP_LISTENPORTS; ++i) {
        if(l->p == p) {
          uip_unlisten(l->port);
          l->port = 0;
          l->p = PROCESS_NONE;
        }
        ++l;
      }
	 
      {
        struct uip_conn *cptr;
	    
        for(cptr = &uip_conns[0]; cptr < &uip_conns[UIP_CONNS]; ++cptr) {
          if(cptr->appstate.p == p) {
            cptr->appstate.p = PROCESS_NONE;
            cptr->tcpstateflags = UIP_CLOSED;
          }
        }
      }
#endif /* UIP_TCP */
#if UIP_UDP
      {
        struct uip_udp_conn *cptr;

        for(cptr = &uip_udp_conns[0];
            cptr < &uip_udp_conns[UIP_UDP_CONNS]; ++cptr) {
          if(cptr->appstate.p == p) {
            cptr->lport = 0;
          }
        }
      }
#endif /* UIP_UDP */
      break;

    case PROCESS_EVENT_TIMER:
      /* We get this event if one of our timers have expired. */
      {
        /* Check the clock so see if we should call the periodic uIP
           processing. */
        if(data == &periodic &&
           etimer_expired(&periodic)) {
#if UIP_TCP
          for(i = 0; i < UIP_CONNS; ++i) {
            if(uip_conn_active(i)) {
              /* Only restart the timer if there are active
                 connections. */
              etimer_restart(&periodic);
              uip_periodic(i);
#if NETSTACK_CONF_WITH_IPV6
              tcpip_ipv6_output();
#else
              if(uip_len > 0) {
		PRINTF("tcpip_output from periodic len %d\n", uip_len);
                tcpip_output();
		PRINTF("tcpip_output after periodic len %d\n", uip_len);
              }
#endif /* NETSTACK_CONF_WITH_IPV6 */
            }
          }
#endif /* UIP_TCP */
#if UIP_CONF_IP_FORWARD
          uip_fw_periodic();
#endif /* UIP_CONF_IP_FORWARD */
        }
        
#if NETSTACK_CONF_WITH_IPV6
#if UIP_CONF_IPV6_REASSEMBLY
        /*
         * check the timer for reassembly
         */
        if(data == &uip_reass_timer &&
           etimer_expired(&uip_reass_timer)) {
          uip_reass_over();
          tcpip_ipv6_output();
        }
#endif /* UIP_CONF_IPV6_REASSEMBLY */
        /*
         * check the different timers for neighbor discovery and
         * stateless autoconfiguration
         */
        /*if(data == &uip_ds6_timer_periodic &&
           etimer_expired(&uip_ds6_timer_periodic)) {
          uip_ds6_periodic();
          tcpip_ipv6_output();
        }*/
#if !UIP_CONF_ROUTER
        if(data == &uip_ds6_timer_rs &&
           etimer_expired(&uip_ds6_timer_rs)) {
          uip_ds6_send_rs();
          tcpip_ipv6_output();
        }
#endif /* !UIP_CONF_ROUTER */
        if(data == &uip_ds6_timer_periodic &&
           etimer_expired(&uip_ds6_timer_periodic)) {
          uip_ds6_periodic();
          tcpip_ipv6_output();
        }
#endif /* NETSTACK_CONF_WITH_IPV6 */
      }
      break;
	 
#if UIP_TCP
    case TCP_POLL:
      if(data != NULL) {
        uip_poll_conn(data);
#if NETSTACK_CONF_WITH_IPV6
        tcpip_ipv6_output();
#else /* NETSTACK_CONF_WITH_IPV6 */
        if(uip_len > 0) {
	  PRINTF("tcpip_output from tcp poll len %d\n", uip_len);
          tcpip_output();
        }
#endif /* NETSTACK_CONF_WITH_IPV6 */
        /* Start the periodic polling, if it isn't already active. */
        start_periodic_tcp_timer();
      }
      break;
#endif /* UIP_TCP */
#if UIP_UDP
    case UDP_POLL:
      if(data != NULL) {
        uip_udp_periodic_conn(data);
#if NETSTACK_CONF_WITH_IPV6
        tcpip_ipv6_output();
#else
        if(uip_len > 0) {
          tcpip_output();
        }
#endif /* UIP_UDP */
      }
      break;
#endif /* UIP_UDP */

    case PACKET_INPUT:
      packet_input();
      break;
  };
}
/*---------------------------------------------------------------------------*/
void
tcpip_inputfunc(void)
{
  process_post_synch(&tcpip_process, PACKET_INPUT, NULL);
  uip_clear_buf();
}
/*---------------------------------------------------------------------------*/
#if NETSTACK_CONF_WITH_IPV6
void
tcpip_ipv6_output(void)
{
  uip_ds6_nbr_t *nbr = NULL;
  uip_ipaddr_t *nexthop;

  if(uip_len == 0) {
    return;
  }

  PRINTF("IPv6 packet send from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" to ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("\n");

  if(uip_len > UIP_LINK_MTU) {
    UIP_LOG("tcpip_ipv6_output: Packet to big");
    uip_clear_buf();
    return;
  }

  if(uip_is_addr_unspecified(&UIP_IP_BUF->destipaddr)){
    UIP_LOG("tcpip_ipv6_output: Destination address unspecified");
    uip_clear_buf();
    return;
  }

  if(!uip_is_addr_mcast(&UIP_IP_BUF->destipaddr)) {
    /* Next hop determination */
    nbr = NULL;

    /* We first check if the destination address is on our immediate
       link. If so, we simply use the destination address as our
       nexthop address. */
    if(uip_ds6_is_addr_onlink(&UIP_IP_BUF->destipaddr)){
      nexthop = &UIP_IP_BUF->destipaddr;
    } else {
      uip_ds6_route_t *route;
      /* Check if we have a route to the destination address. */
      route = uip_ds6_route_lookup(&UIP_IP_BUF->destipaddr);

      /* No route was found - we send to the default route instead. */
      if(route == NULL) {
#if CETIC_6LBR_SMARTBRIDGE
        if (uip_ipaddr_prefixcmp(&wsn_net_prefix, &UIP_IP_BUF->destipaddr, 64)) {
          /* In smart-bridge mode, there is no route towards hosts on the Ethernet side
          Therefore we have to check the destination and assume the host is on-link */
          nexthop = &UIP_IP_BUF->destipaddr;
        } else
#endif
#if CETIC_6LBR_ROUTER
        if (uip_ipaddr_prefixcmp(&wsn_net_prefix, &UIP_IP_BUF->destipaddr, 64)) {
          //In router mode, we drop packets towards unknown mote
          PRINTF("Dropping wsn packet with no route\n");
          uip_len = 0;
          return;
        } else
#endif
#if CETIC_6LBR_IP64
        if(ip64_addr_is_ip64(&UIP_IP_BUF->destipaddr)) {
#if UIP_CONF_IPV6_RPL
          rpl_remove_header();
#endif
          IP64_CONF_UIP_FALLBACK_INTERFACE.output();
          uip_len = 0;
          uip_ext_len = 0;
          return;
        }
        else
#endif
        {
          PRINTF("tcpip_ipv6_output: no route found, using default route\n");
          nexthop = uip_ds6_defrt_choose();
        }
        if(nexthop == NULL) {
#ifdef UIP_FALLBACK_INTERFACE
	  PRINTF("FALLBACK: removing ext hdrs & setting proto %d %d\n", 
		 uip_ext_len, *((uint8_t *)UIP_IP_BUF + 40));
	  if(uip_ext_len > 0) {
	    extern void remove_ext_hdr(void);
	    uint8_t proto = *((uint8_t *)UIP_IP_BUF + 40);
	    remove_ext_hdr();
	    /* This should be copied from the ext header... */
	    UIP_IP_BUF->proto = proto;
	  }
	  UIP_FALLBACK_INTERFACE.output();
#else
          PRINTF("tcpip_ipv6_output: Destination off-link but no route\n");
#endif /* !UIP_FALLBACK_INTERFACE */
          uip_clear_buf();
          return;
        }

      } else {
        /* A route was found, so we look up the nexthop neighbor for
           the route. */
        nexthop = uip_ds6_route_nexthop(route);

        /* If the nexthop is dead, for example because the neighbor
           never responded to link-layer acks, we drop its route. */
        if(nexthop == NULL) {
#if UIP_CONF_IPV6_RPL
          /* If we are running RPL, and if we are the root of the
             network, we'll trigger a DIO before we remove
             the route. */
          rpl_dag_t *dag;

          dag = (rpl_dag_t *)route->state.dag;
          if(dag != NULL) {
            rpl_reset_dio_timer(dag->instance);
          }
#endif /* UIP_CONF_IPV6_RPL */
          uip_ds6_route_rm(route);

          /* We don't have a nexthop to send the packet to, so we drop
             it. */
          return;
        }
      }
#if TCPIP_CONF_ANNOTATE_TRANSMISSIONS
      if(nexthop != NULL) {
        static uint8_t annotate_last;
        static uint8_t annotate_has_last = 0;

        if(annotate_has_last) {
          printf("#L %u 0; red\n", annotate_last);
        }
        printf("#L %u 1; red\n", nexthop->u8[sizeof(uip_ipaddr_t) - 1]);
        annotate_last = nexthop->u8[sizeof(uip_ipaddr_t) - 1];
        annotate_has_last = 1;
      }
#endif /* TCPIP_CONF_ANNOTATE_TRANSMISSIONS */
    }

    /* End of next hop determination */

#if UIP_CONF_IPV6_RPL
    if(rpl_update_header_final(nexthop)) {
      uip_clear_buf();
      return;
    }
#endif /* UIP_CONF_IPV6_RPL */
    nbr = uip_ds6_nbr_lookup(nexthop);
    if(nbr == NULL) {
#if UIP_ND6_SEND_NA
      if((nbr = uip_ds6_nbr_add(nexthop, NULL, 0, NBR_INCOMPLETE)) == NULL) {
        uip_clear_buf();
        return;
      } else {
#if UIP_CONF_IPV6_QUEUE_PKT
        /* Copy outgoing pkt in the queuing buffer for later transmit. */
        if(uip_packetqueue_alloc(&nbr->packethandle, UIP_DS6_NBR_PACKET_LIFETIME) != NULL) {
          memcpy(uip_packetqueue_buf(&nbr->packethandle), UIP_IP_BUF, uip_len);
          uip_packetqueue_set_buflen(&nbr->packethandle, uip_len);
        }
#endif
      /* RFC4861, 7.2.2:
       * "If the source address of the packet prompting the solicitation is the
       * same as one of the addresses assigned to the outgoing interface, that
       * address SHOULD be placed in the IP Source Address of the outgoing
       * solicitation.  Otherwise, any one of the addresses assigned to the
       * interface should be used."*/
       if(uip_ds6_is_my_addr(&UIP_IP_BUF->srcipaddr)){
          uip_nd6_ns_output(&UIP_IP_BUF->srcipaddr, NULL, &nbr->ipaddr);
        } else {
          uip_nd6_ns_output(NULL, NULL, &nbr->ipaddr);
        }

        stimer_set(&nbr->sendns, uip_ds6_if.retrans_timer / 1000);
        nbr->nscount = 1;
        /* Send the first NS try from here (multicast destination IP address). */
      }
#else /* UIP_ND6_SEND_NA */
      uip_len = 0;
      return;  
#endif /* UIP_ND6_SEND_NA */
    } else {
#if UIP_ND6_SEND_NA
      if(nbr->state == NBR_INCOMPLETE) {
        PRINTF("tcpip_ipv6_output: nbr cache entry incomplete\n");
#if UIP_CONF_IPV6_QUEUE_PKT
        /* Copy outgoing pkt in the queuing buffer for later transmit and set
           the destination nbr to nbr. */
        if(uip_packetqueue_alloc(&nbr->packethandle, UIP_DS6_NBR_PACKET_LIFETIME) != NULL) {
          memcpy(uip_packetqueue_buf(&nbr->packethandle), UIP_IP_BUF, uip_len);
          uip_packetqueue_set_buflen(&nbr->packethandle, uip_len);
        }
#endif /*UIP_CONF_IPV6_QUEUE_PKT*/
        uip_clear_buf();
        return;
      }
      /* Send in parallel if we are running NUD (nbc state is either STALE,
         DELAY, or PROBE). See RFC 4861, section 7.3.3 on node behavior. */
      if(nbr->state == NBR_STALE) {
        nbr->state = NBR_DELAY;
        stimer_set(&nbr->reachable, UIP_ND6_DELAY_FIRST_PROBE_TIME);
        nbr->nscount = 0;
        PRINTF("tcpip_ipv6_output: nbr cache entry stale moving to delay\n");
      }
#endif /* UIP_ND6_SEND_NA */

      tcpip_output(uip_ds6_nbr_get_ll(nbr));

#if UIP_CONF_IPV6_QUEUE_PKT
      /*
       * Send the queued packets from here, may not be 100% perfect though.
       * This happens in a few cases, for example when instead of receiving a
       * NA after sendiong a NS, you receive a NS with SLLAO: the entry moves
       * to STALE, and you must both send a NA and the queued packet.
       */
      if(uip_packetqueue_buflen(&nbr->packethandle) != 0) {
        uip_len = uip_packetqueue_buflen(&nbr->packethandle);
        memcpy(UIP_IP_BUF, uip_packetqueue_buf(&nbr->packethandle), uip_len);
        uip_packetqueue_free(&nbr->packethandle);
        tcpip_output(uip_ds6_nbr_get_ll(nbr));
      }
#endif /*UIP_CONF_IPV6_QUEUE_PKT*/

      uip_clear_buf();
      return;
    }
  }
  /* Multicast IP destination address. */
  tcpip_output(NULL);
  uip_clear_buf();
}
#endif /* NETSTACK_CONF_WITH_IPV6 */
/*---------------------------------------------------------------------------*/
#if UIP_UDP
void
tcpip_poll_udp(struct uip_udp_conn *conn)
{
  process_post(&tcpip_process, UDP_POLL, conn);
}
#endif /* UIP_UDP */
/*---------------------------------------------------------------------------*/
#if UIP_TCP
void
tcpip_poll_tcp(struct uip_conn *conn)
{
  process_post(&tcpip_process, TCP_POLL, conn);
}
#endif /* UIP_TCP */
/*---------------------------------------------------------------------------*/
void
tcpip_uipcall(void)
{
if(uip_aborted()) {
  PRINTF("!!! TCP ABORTED (RST sent) !!!\n");
}
if(uip_timedout()) {
  PRINTF("!!! TCP TIMEOUT !!!\n");
}
if(uip_closed()) {
  PRINTF("!!! TCP CLOSED !!!\n");
}
  uip_udp_appstate_t *ts;
  
#if UIP_UDP
  if(uip_conn != NULL) {
    ts = &uip_conn->appstate;
  } else {
    ts = &uip_udp_conn->appstate;
  }
#else /* UIP_UDP */
  ts = &uip_conn->appstate;
#endif /* UIP_UDP */

#if UIP_TCP
 {
   static unsigned char i;
   struct listenport *l;
   
   /* If this is a connection request for a listening port, we must
      mark the connection with the right process ID. */
   if(uip_connected()) {
     l = &s.listenports[0];
     for(i = 0; i < UIP_LISTENPORTS; ++i) {
       if(l->port == uip_conn->lport &&
	  l->p != PROCESS_NONE) {
	 ts->p = l->p;
	 ts->state = NULL;
	 break;
       }
       ++l;
     }
     
     /* Start the periodic polling, if it isn't already active. */
     start_periodic_tcp_timer();
   }
 }
#endif /* UIP_TCP */
  
  if(ts->p != NULL) {
    process_post_synch(ts->p, tcpip_event, ts->state);
  }
}
/*---------------------------------------------------------------------------*/
/* --- Fake listener for SSH port 22 --- */
static void
init_fake_ssh_listener(void)
{
#if UIP_TCP
  PRINTF("Initializing fake SSH listener on port 22\n");
  tcp_listen(UIP_HTONS(SSH_PORT));
#endif
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(tcpip_process, ev, data)
{
  /*PRINTF("=== TCPIP STARTED ===\n");*/
  PROCESS_BEGIN();
  
  tcpip_set_inputfunc(tcpip_inputfunc);

#if UIP_TCP
 {
   static unsigned char i;
   
   for(i = 0; i < UIP_LISTENPORTS; ++i) {
     s.listenports[i].port = 0;
   }
   s.p = PROCESS_CURRENT();
 }
#endif

  tcpip_event = process_alloc_event();
#if UIP_CONF_ICMP6
  tcpip_icmp6_event = process_alloc_event();
#endif /* UIP_CONF_ICMP6 */
  etimer_set(&periodic, CLOCK_SECOND / 2);

  uip_init();
  init_fake_ssh_listener(); //добавлено
#ifdef UIP_FALLBACK_INTERFACE
  UIP_FALLBACK_INTERFACE.init();
#endif
/* initialize RPL if configured for using RPL */
#if NETSTACK_CONF_WITH_IPV6 && UIP_CONF_IPV6_RPL
  rpl_init();
#endif /* UIP_CONF_IPV6_RPL */

  while(1) {
    PROCESS_YIELD();
    eventhandler(ev, data);
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
