#include "backbone.h"
#include <stdio.h>
#include <lwip/ip.h>
#include <unistd.h>
#include <fcntl.h>

#include "lwip/init.h"
#include "lwip/sys.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/stats.h"

err_t
udpif_init(struct netif *netif);

sys_sem_t lwip_init_done;
struct netif phyif;
int is_server = 0;
#define IFNAME0 't'
#define IFNAME1 'p'



/** @rief Callback for lwIP init completion.
 *
 * This callback is automatically called from the lwIP thread after the
 * initialization is complete. It must then tell the main init task that it
 * can proceed. To do thism we use a semaphore that is posted from the lwIP
 * thread and on which the main init task is pending. */
void ipinit_done_cb(void *a)
{
    sys_sem_signal(&lwip_init_done);
}

/** @brief Inits the IP stack and the network interfaces.
 *
 * This function is responsible for the following :
 * 1. Initialize the lwIP library.
 * 2. Wait for lwIP init to be complete.
 * 3. Create the SLIP interface and give it a static adress/netmask.
 * 4. Set the SLIP interface as default and create a gateway.
 * 5. List all network interfaces and their settings, for debug purposes.
 */
void ub_stack_init(uint32_t ip_addr) {
    /* Netif configuration */
    static ip_addr_t  ipaddr,netmask, gw;

    (ipaddr).addr = ip_addr;
    IP4_ADDR(&netmask, 255,255,255,0);

    /* Creates the "Init done" semaphore. */
    sys_sem_new(&lwip_init_done, 0);

    /* We start the init of the IP stack. */
    tcpip_init(ipinit_done_cb, NULL);

    /* We wait for the IP stack to be fully initialized. */
    printf("Waiting for LWIP init...\n");
    sys_sem_wait(&lwip_init_done);

    /* Deletes the init done semaphore. */
    sys_sem_free(&lwip_init_done);
    printf("LWIP init complete\n");

    /* Adds a tap pseudo interface for unix debugging. */
    netif_add(&phyif, &ipaddr, &netmask, &gw, &is_server, udpif_init, tcpip_input);

    netif_set_default(&phyif);
    netif_set_up(&phyif);

}

struct BACKBONE udp_backbone = {
    ub_stack_init
};


#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "lwip/opt.h"

#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"
#include <netinet/in.h>


#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
struct udpif {
  /* Add whatever per-interface state that is needed here. */
    int udpfd, nready, maxfdp1;
    struct sockaddr_in cliaddr;
    char buffer[8000];
    char rbuffer[8000];
    fd_set rset;
};

/* Forward declarations. */
static void udpif_input(struct netif *netif);
#if !NO_SYS
static void udpif_thread(void *arg);
#endif /* !NO_SYS */

/*-----------------------------------------------------------------------------------*/
static void
low_level_init(struct netif *netif, int port)
{
  struct udpif *udpif;
  int ret;
  udpif = (struct udpif *)netif->state;

  /* Obtain MAC address from network interface. */

  /* (We just fake an address...) */
  netif->hwaddr[0] = 0x02;
  netif->hwaddr[1] = 0x12;
  netif->hwaddr[2] = 0x34;
  netif->hwaddr[3] = 0x56;
  netif->hwaddr[4] = 0x78;
  netif->hwaddr[5] = 0xab;
  netif->hwaddr_len = 6;

  /* device capabilities */
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

    int listenfd, connfd, udpfd, nready, maxfdp1;
    pid_t childpid;
    fd_set rset;
    ssize_t n;
    socklen_t len;
    const int on = 1;
    struct sockaddr_in servaddr;
    char* message = "Hello Client";
    void sig_chld(int);
    int error = 0;


    /* create UDP socket */
    udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    // binding server addr structure to udp sockfd
    bind(udpfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    // clear the descriptor set
    FD_ZERO(&udpif->rset);
    udpif->udpfd = udpfd;

    if (error) {
      LWIP_DEBUGF(TAPIF_DEBUG, ("udpif_init: error %d\n", error));
        exit(1);
    }


  netif_set_link_up(netif);

 sys_thread_new("udpif_thread", udpif_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t
low_level_output(struct netif *netif, struct pbuf *p)
{
  struct udpif *udpif = (struct udpif *)netif->state;
  char buf[1518]; /* max packet size including VLAN excluding CRC */
  ssize_t written;

#if 0
  if (((double)rand()/(double)RAND_MAX) < 0.2) {
    printf("drop output\n");
    return ERR_OK; /* ERR_OK because we simulate packet loss on cable */
  }
#endif

  if (p->tot_len > sizeof(buf)) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("udpif: packet too large");
    return ERR_IF;
  }

  /* initiate transfer(); */
  pbuf_copy_partial(p, buf, p->tot_len, 0);

  /* signal that packet should be sent(); */
  sendto(udpif->udpfd, buf, p->tot_len, 0, (struct sockaddr*)&(udpif->cliaddr), sizeof(udpif->cliaddr));

    return ERR_OK;
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *
low_level_input(struct netif *netif)
{
  struct udpif *udpif = (struct udpif *)netif->state;

    // if udp socket is readable receive the message.
    if (FD_ISSET(udpif->udpfd, &udpif->rset)) {
        ssize_t n;
        socklen_t len;

        len = sizeof(udpif->cliaddr);
        bzero(udpif->rbuffer, sizeof(udpif->rbuffer));
        n = recvfrom(udpif->udpfd, udpif->rbuffer, sizeof(udpif->rbuffer), 0,
                        (struct sockaddr*)&(udpif->cliaddr), &len);
        if (n) {
            struct pbuf *p;
            printf("\nMessage from UDP client: ");

            u16_t len = n;
            MIB2_STATS_NETIF_ADD(netif, ifinoctets, len);

            /* We allocate a pbuf chain of pbufs from the pool. */
            p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
            if (p != NULL) {
                pbuf_take(p, udpif->rbuffer, len);
                /* acknowledge that packet has been read(); */
            } else {
                /* drop packet(); */
                MIB2_STATS_NETIF_INC(netif, ifindiscards);
                LWIP_DEBUGF(NETIF_DEBUG, ("udpif_input: could not allocate pbuf\n"));
            }

            return p;

        }

    }
    return NULL;
}

/*-----------------------------------------------------------------------------------*/
/*
 * udpif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void
udpif_input(struct netif *netif)
{
  struct pbuf *p = low_level_input(netif);

  if (p == NULL) {
#if LINK_STATS
    LINK_STATS_INC(link.recv);
#endif /* LINK_STATS */
    LWIP_DEBUGF(TAPIF_DEBUG, ("udpif_input: low_level_input returned NULL\n"));
    return;
  }

  if (netif->input(p, netif) != ERR_OK) {
    LWIP_DEBUGF(NETIF_DEBUG, ("udpif_input: netif input error\n"));
    pbuf_free(p);
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * udpif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t
udpif_init(struct netif *netif)
{
  struct udpif *udpif = (struct udpif *)mem_malloc(sizeof(struct udpif));

  if (udpif == NULL) {
    LWIP_DEBUGF(NETIF_DEBUG, ("udpif_init: out of memory for udpif\n"));
    return ERR_MEM;
  }
  netif->state = udpif;
  MIB2_INIT_NETIF(netif, snmp_ifType_other, 100000000);

  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
#if LWIP_IPV4
  netif->output = etharp_output;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
  netif->linkoutput = low_level_output;
  netif->mtu = 1500;

  int port = 6969; // TPD: something else?
  low_level_init(netif, port);

  return ERR_OK;
}


/*-----------------------------------------------------------------------------------*/
void
udpif_poll(struct netif *netif)
{
  udpif_input(netif);
}

#if NO_SYS

int
udpif_select(struct netif *netif)
{
  fd_set fdset;
  int ret;
  struct timeval tv;
  struct udpif *udpif;
  u32_t msecs = sys_timeouts_sleeptime();

  udpif = (struct udpif *)netif->state;

  tv.tv_sec = msecs / 1000;
  tv.tv_usec = (msecs % 1000) * 1000;

  FD_ZERO(&fdset);
  FD_SET(udpif->fd, &fdset);

  ret = select(udpif->fd + 1, &fdset, NULL, NULL, &tv);
  if (ret > 0) {
    udpif_input(netif);
  }
  return ret;
}

#else /* NO_SYS */

static void
udpif_thread(void *arg)
{
  struct netif *netif;
  struct udpif *udpif;
  fd_set fdset;
  int ret;

  netif = (struct netif *)arg;
  udpif = (struct udpif *)netif->state;

  while(1) {
    FD_ZERO(&fdset);
    FD_SET(udpif->udpfd, &fdset);

    /* Wait for a packet to arrive. */
    ret = select(udpif->udpfd + 1, &fdset, NULL, NULL, NULL);

    if(ret == 1) {
      /* Handle incoming packet. */
      udpif_input(netif);
    } else if(ret == -1) {
      perror("udpif_thread: select");
    }
  }
}

#endif /* NO_SYS */
