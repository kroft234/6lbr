/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */
/**
 * \file
 * border-router
 * \author
 * Niclas Finne <nfi@sics.se>
 * Joakim Eriksson <joakime@sics.se>
 * Nicolas Tsiftes <nvt@sics.se>
 */
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/rpl/rpl.h"
#include "net/ipv6/sicslowpan.h"  // ДОБАВЛЕНО: нужно для sicslowpan_get_last_rssi()
#include "net/netstack.h"
#include "dev/button-sensor.h"
#include "dev/slip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEBUG DEBUG_NONE
#include "net/ip/uip-debug.h"

// ДОБАВЛЕНО: новые глобальные переменные и константы
uip_ipaddr_t inside_prefix; 
static uip_ipaddr_t prefix;
uint8_t time_blink;
uint8_t device_type_seting;
#define ROUTER_TYPE 1
#define TARGET_TYPE 2
static int def_rt_rssi = 0;

PROCESS(border_router_process, "Border router process");

#if WEBSERVER==0
/* No webserver */
AUTOSTART_PROCESSES(&border_router_process);
#elif WEBSERVER>1
/* Use an external webserver application */
#include "webserver-nogui.h"
AUTOSTART_PROCESSES(&border_router_process,&webserver_nogui_process);
#else
/* Use simple webserver with only one page for minimum footprint. */
#include "httpd-simple.h"

#define WEBSERVER_CONF_LOADTIME 0
#define WEBSERVER_CONF_FILESTATS 0
#define WEBSERVER_CONF_NEIGHBOR_STATUS 0
#define WEBSERVER_CONF_ROUTE_LINKS 0
#if WEBSERVER_CONF_ROUTE_LINKS
#define BUF_USES_STACK 1
#endif

PROCESS(webserver_nogui_process, "Web server");
PROCESS_THREAD(webserver_nogui_process, ev, data)
{
  PROCESS_BEGIN();
  httpd_init();
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == tcpip_event);
    httpd_appcall(data);
  }
  PROCESS_END();
}

AUTOSTART_PROCESSES(&border_router_process,&webserver_nogui_process);

static const char *TOP = "<html><head><title>ContikiRPL</title></head><body>\n";
static const char *BOTTOM = "</body></html>\n";

#if BUF_USES_STACK
static char *bufptr, *bufend;
#define ADD(...) do { \
    bufptr += snprintf(bufptr, bufend - bufptr, __VA_ARGS__); \
  } while(0)
#else
static char buf[256];
static int blen;
#define ADD(...) do { \
    blen += snprintf(&buf[blen], sizeof(buf) - blen, __VA_ARGS__); \
  } while(0)
#endif

/*---------------------------------------------------------------------------*/
static void
ipaddr_add(const uip_ipaddr_t *addr)
{
  uint16_t a;
  int i, f;
  for(i = 0, f = 0; i < sizeof(uip_ipaddr_t); i += 2) {
    a = (addr->u8[i] << 8) + addr->u8[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0) ADD("::");
    } else {
      if(f > 0) {
        f = -1;
      } else if(i > 0) {
        ADD(":");
      }
      ADD("%x", a);
    }
  }
}

/*---------------------------------------------------------------------------*/
static
PT_THREAD(generate_routes(struct httpd_state *s))
{
  static uip_ds6_route_t *r;
  static uip_ds6_nbr_t *nbr;
  uint8_t channel_temp; // ДОБАВЛЕНО: переменная для канала
#if BUF_USES_STACK
  char buf[256];
#endif
#if WEBSERVER_CONF_LOADTIME
  static clock_time_t numticks;
  numticks = clock_time();
#endif
  PSOCK_BEGIN(&s->sout);
  SEND_STRING(&s->sout, TOP);
#if BUF_USES_STACK
  bufptr = buf;bufend=bufptr+sizeof(buf);
#else
  blen = 0;
#endif
  ADD("Neighbors<pre>");
  for(nbr = nbr_table_head(ds6_neighbors);
      nbr != NULL;
      nbr = nbr_table_next(ds6_neighbors, nbr)) {
#if WEBSERVER_CONF_NEIGHBOR_STATUS
#if BUF_USES_STACK
{char* j=bufptr+25;
      ipaddr_add(&nbr->ipaddr);
      while (bufptr < j) ADD(" ");
      switch (nbr->state) {
      case NBR_INCOMPLETE: ADD(" INCOMPLETE");break;
      case NBR_REACHABLE: ADD(" REACHABLE");break;
      case NBR_STALE: ADD(" STALE");break;
      case NBR_DELAY: ADD(" DELAY");break;
      case NBR_PROBE: ADD(" NBR_PROBE");break;
      }
}
#else
{uint8_t j=blen+25;
      ipaddr_add(&nbr->ipaddr);
      while (blen < j) ADD(" ");
      switch (nbr->state) {
      case NBR_INCOMPLETE: ADD(" INCOMPLETE");break;
      case NBR_REACHABLE: ADD(" REACHABLE");break;
      case NBR_STALE: ADD(" STALE");break;
      case NBR_DELAY: ADD(" DELAY");break;
      case NBR_PROBE: ADD(" NBR_PROBE");break;
      }
}
#endif
#else
      ipaddr_add(&nbr->ipaddr);
#endif
      ADD("\n");
#if BUF_USES_STACK
      if(bufptr > bufend - 45) {
        SEND_STRING(&s->sout, buf);
        bufptr = buf; bufend = bufptr + sizeof(buf);
      }
#else
      if(blen > sizeof(buf) - 45) {
        SEND_STRING(&s->sout, buf);
        blen = 0;
      }
#endif
  }
  ADD("</pre>Routes<pre>");
  SEND_STRING(&s->sout, buf);
#if BUF_USES_STACK
  bufptr = buf; bufend = bufptr + sizeof(buf);
#else
  blen = 0;
#endif
  for(r = uip_ds6_route_head(); r != NULL; r = uip_ds6_route_next(r)) {
#if BUF_USES_STACK
#if WEBSERVER_CONF_ROUTE_LINKS
    ADD("<a href=http://[");
    ipaddr_add(&r->ipaddr);
    ADD("]/status.shtml>");
    ipaddr_add(&r->ipaddr);
    ADD("</a>");
#else
    ipaddr_add(&r->ipaddr);
#endif
#else
#if WEBSERVER_CONF_ROUTE_LINKS
    ADD("<a href=http://[");
    ipaddr_add(&r->ipaddr);
    ADD("]/status.shtml>");
    SEND_STRING(&s->sout, buf);
    blen = 0;
    ipaddr_add(&r->ipaddr);
    ADD("</a>");
#else
    ipaddr_add(&r->ipaddr);
#endif
#endif
    ADD("/%u (via ", r->length);
    ipaddr_add(uip_ds6_route_nexthop(r));
    if(1 || (r->state.lifetime < 600)) {
      ADD(") %lus\n", (unsigned long)r->state.lifetime);
    } else {
      ADD(")\n");
    }
    SEND_STRING(&s->sout, buf);
#if BUF_USES_STACK
    bufptr = buf; bufend = bufptr + sizeof(buf);
#else
    blen = 0;
#endif
  }
  // ДОБАВЛЕНО: информация о RSSI, канале и мощности передачи
  def_rt_rssi = sicslowpan_get_last_rssi();
  ADD("%i RSSI\n", def_rt_rssi);
  channel_temp = get_channel();
  ADD("%d Radio_channel\n", channel_temp);
  int power; //power in dbm with cc2592 chip
  power = get_tx_power_cc2592();
  ADD("%i transmition_power\n", power);
  ADD("</pre>");
#if WEBSERVER_CONF_FILESTATS
  static uint16_t numtimes;
  ADD("<br><i>This page sent %u times</i>",++numtimes);
#endif
#if WEBSERVER_CONF_LOADTIME
  numticks = clock_time() - numticks + 1;
  ADD(" <i>(%u.%02u sec)</i>",numticks/CLOCK_SECOND,(100*(numticks%CLOCK_SECOND))/CLOCK_SECOND));
#endif
  SEND_STRING(&s->sout, buf);
  SEND_STRING(&s->sout, BOTTOM);
  PSOCK_END(&s->sout);
}

/*---------------------------------------------------------------------------*/
httpd_simple_script_t
httpd_simple_get_script(const char *name)
{
  return generate_routes;
}
#endif /* WEBSERVER */

/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;
  PRINTA("Server IPv6 addresses:\n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINTA(" ");
      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTA("\n");
    }
  }
}

/*---------------------------------------------------------------------------*/
void
request_prefix(void)
{
  uip_buf[0] = '?';
  uip_buf[1] = 'P';
  uip_len = 2;
  slip_send();
  uip_clear_buf();
}

/*---------------------------------------------------------------------------*/
// ДОБАВЛЕНО: новая функция request_power
static void
request_power(void)
{
  uip_buf[0] = '?';
  uip_buf[1] = 'T';
  uip_len = 2;
  slip_send();
  uip_clear_buf();
}

/*---------------------------------------------------------------------------*/
void
set_prefix_64(uip_ipaddr_t *prefix_64)
{
  uip_ipaddr_t ipaddr;
  memcpy(&prefix, prefix_64, 16);
  memcpy(&ipaddr, prefix_64, 16);

  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);

  // Самое важное — сохраняем полный адрес для блока TARGET_TYPE
  memcpy(&inside_prefix, &ipaddr, sizeof(uip_ipaddr_t));

  // Добавляем адрес в uIP-стек > Linux должен увидеть его
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  PRINTF("Prefix received and address added to uIP: ");
  uip_debug_ipaddr_print(&ipaddr);
  PRINTF("\n");

  // НЕ устанавливаем device_type_seting = 1
  // НЕ создаём DAG root — это только для роутера!
    // --- ДОБАВЛЯЕМ запись в файл для Linux ---
    FILE *f = fopen("/var/log/6lbr.ip", "w");
    if(f) {
        fprintf(f, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
            ipaddr.u8[0], ipaddr.u8[1], ipaddr.u8[2], ipaddr.u8[3],
            ipaddr.u8[4], ipaddr.u8[5], ipaddr.u8[6], ipaddr.u8[7],
            ipaddr.u8[8], ipaddr.u8[9], ipaddr.u8[10], ipaddr.u8[11],
            ipaddr.u8[12], ipaddr.u8[13], ipaddr.u8[14], ipaddr.u8[15]);
        fclose(f);
    }
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(border_router_process, ev, data)
{
  static struct etimer et;
  PROCESS_BEGIN();

  device_type_seting = TARGET_TYPE;  // ИЗМЕНЕНО: теперь 0, а не prefix_set
  NETSTACK_MAC.off(0);
  PROCESS_PAUSE();

  // ДОБАВЛЕНО: закомментированная строка, можно раскомментировать при необходимости
  // slip_arch_init(115200*4);

  SENSORS_ACTIVATE(button_sensor);

  while(!device_type_seting) {
    etimer_set(&et, CLOCK_SECOND);
    request_prefix();
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  }

  request_power();  // ДОБАВЛЕНО: вызов новой функции

  NETSTACK_MAC.off(1);

#if DEBUG || 1
  print_local_addresses();
#endif

  PRINTF("UIP_CONF_TCP_MSS %u \n",UIP_CONF_TCP_MSS);

  while(1) {
    etimer_set(&et, CLOCK_SECOND*time_blink);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);

    // ДОБАВЛЕНО: блок для TARGET_TYPE — регистрация префикса в Linux-стеке
    if (device_type_seting){
      // uip_over_mesh_make_announced_gateway();
      leds_toggle(LEDS_GREEN);
    }
    if (device_type_seting==TARGET_TYPE){
      unsigned char finded,not_first,i;
      finded =0;
      not_first=0;
      for (i=0;i<UIP_DS6_ADDR_NB;i++){
        if(uip_ipaddr_prefixcmp(&uip_ds6_if.addr_list[i].ipaddr, &inside_prefix, 128)
            && uip_ds6_if.addr_list[i].isused){
          finded=i+1;
          break;
        }else if(uip_ds6_if.addr_list[i].isused){
          not_first=1;
        }
      }
      if(finded){
        PRINTF("FINDED SELF ADDRESS\n");
        if(not_first){
          PRINTF("SELF ADDRESS NOT FIRST\n");
          PRINT6ADDR(&inside_prefix);
          for(i=0;i<(finded-1);i++){
            uip_ds6_addr_rm(&uip_ds6_if.addr_list[i]);
          }
          uip_ds6_addr_add(&inside_prefix, 0, ADDR_AUTOCONF);
        }else{
          PRINTF("SELF ADDRESS FIRST\n");
        }
      }else{
        PRINTF("DON'T FINDED SELF ADDRESS\n");
        PRINT6ADDR(&inside_prefix);
        uip_ds6_addr_add(&inside_prefix, 0, ADDR_AUTOCONF);
      }
    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/