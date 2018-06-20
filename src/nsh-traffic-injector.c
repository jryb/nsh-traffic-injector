/*-
 * nsh-traffic-injector.c - Add NSH Service chaining headers to pakcets from a PCAP file
 *               to validate service functions
 *
 * Copyright (c) 2018, Jeff Rybczynski <jeff.rybczynski@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "field_extractor.h"

/*
 * Debugging functions and switch
 */
static bool g_debug = false;
#define PRINT_DEBUG(str, ...)                    \
    if (g_debug) printf(str, ##__VA_ARGS__);

/*
 * Globals
 */
static bool g_recreate_real_time = true;
static int g_total_pkts = 0;
static int g_pcap_total_pkt_cnt = 0;
static int g_pkt_cnt = 0;
static int g_sd = 0;
static pcap_t *g_handle;
static bool g_show_percent = true;

/*
 * NSH Protocol number for GRE header
 */
#define GRE_NSH_PROTOCOL 0x894F

/*
 * Max vectors for iovec send_msg
 */
#define MAX_VECTORS 3

/*
 * NSH MD type 1 header
 */
struct nsh_hdr {
    uint8_t ver_oc;
    uint8_t length;
    uint8_t type;
    uint8_t next_protocol;
    uint32_t svc_path_index;
    uint32_t context[4];
}__attribute__((packed));

/*
 * Headers to add to make this a service chaining packet
 */
static struct fe_gre_base default_gre;
static struct nsh_hdr default_nsh;
static struct sockaddr_in d_addr;
static char *dst_ip_addr = "127.0.0.1";

/*
 * Initialize raw socket to send GRE/NSH packet to service function
 */
static void init_nsh_socket (void) {
    g_sd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (g_sd < 0) {
        perror("socket() failed");
        exit (EXIT_FAILURE);
    }

    default_gre.flags = 0;
    default_gre.next_prot = htons(GRE_NSH_PROTOCOL);

    default_nsh.ver_oc = 0;
    default_nsh.length = 0x6;
    default_nsh.type = 0x1;
    default_nsh.next_protocol = 0x1;
    default_nsh.svc_path_index = ntohl(0x12345678);

    d_addr.sin_family = AF_INET;
    inet_aton(dst_ip_addr, &d_addr.sin_addr);
}

/*
 * Time stamp info
 */
static struct timeval prog_start_tv;
static struct timeval now_tv;
static struct timeval pcap_start_tv;

/*
 * Per packet packet handlers
 */
/*
 * Count the total number of packets in a PCAP file so we can display the
 * progress properly.  This is especially useful when doing real-time replay
 */
static void total_packet_cnt (u_char *args,
			      const struct pcap_pkthdr *packet_header,
			      const u_char *packet_body)
{
    g_pcap_total_pkt_cnt++;
}


/*
 * Take the IP packet and add an NSH and GRE header to the packet.
 * Send service chaining NSH packet to service function to test.
 */
static int prev_percent = 0;

static void packet_handler (u_char *args,
                            const struct pcap_pkthdr *packet_header,
                            const u_char *packet_body)
{
    struct msghdr msg;
    struct iovec io[MAX_VECTORS];
    const u_char *eth_hdr = packet_body;
    const u_char *ip_hdr = GET_L3_START(eth_hdr);
    ssize_t tx_bytes;
    uint32_t prog_usec_diff, pcap_usec_diff;

    /*
     * Have we seen all the packets?
     */
    if (g_pkt_cnt && g_pkt_cnt <= g_total_pkts) {
        pcap_breakloop(g_handle);
        return;
    }

    /*
     * Display progress
     */
    if (g_show_percent) {
        int percent = (g_total_pkts * 100)/g_pcap_total_pkt_cnt;
        if (percent - prev_percent >=1) {
            printf("\b\b\b%2d%%", percent);
            fflush(stdout);
            prev_percent = percent;
        }
    } else {
        if (g_total_pkts % 1000 == 0) {
            printf("\b\b\b\b\b\b\b\b\b\b\b\b%12d", g_total_pkts);
            fflush(stdout);
        }
    }

    /*
     * We currently only support IP packets.
     * NSH supports on IP packets (at least officially) on Cisco IOS-XE
     */
    if (GET_ETHERTYPE(eth_hdr) != ETHERTYPE_IPV4 &&
        GET_ETHERTYPE(eth_hdr) != ETHERTYPE_IPV6) {
        PRINT_DEBUG("Invalid L3 Ethertype 0x%x\n", GET_ETHERTYPE(eth_hdr));
        return;
    }

    /*
     * Validate IP version
     */
    if (GET_IP_VER(ip_hdr) != 0x4 &&
        GET_IP_VER(ip_hdr) != 0x6){
        PRINT_DEBUG("Invalid IP protocol %x\n", GET_IP_VER(ip_hdr));
        return;
    }

    if (g_total_pkts == 0) {
        /*
         * This is the first pkt.  Cache time values.
         */
        pcap_start_tv.tv_sec = packet_header->ts.tv_sec;
        pcap_start_tv.tv_usec = packet_header->ts.tv_usec;
        PRINT_DEBUG("Set pcap first pkt time to %ld.%06ld\n",
                    pcap_start_tv.tv_sec, pcap_start_tv.tv_usec);
        (void)gettimeofday(&prog_start_tv, NULL);
        PRINT_DEBUG("Set prog start time to %ld.%06ld\n", prog_start_tv.tv_sec,
                    prog_start_tv.tv_usec);
    }

    /*
     * Calculate time deltas to see if we should wait
     */
    (void)gettimeofday(&now_tv, NULL);
    prog_usec_diff = ((1000000 * (now_tv.tv_sec - prog_start_tv.tv_sec)) +
                      (now_tv.tv_usec - prog_start_tv.tv_usec));
    pcap_usec_diff = ((1000000 *
                       (packet_header->ts.tv_sec - pcap_start_tv.tv_sec)) +
                      (packet_header->ts.tv_usec - pcap_start_tv.tv_usec));
    if (prog_usec_diff < pcap_usec_diff) {
        PRINT_DEBUG("Wait %d usecs to send this packet\n",
                    pcap_usec_diff - prog_usec_diff);
        if (g_recreate_real_time)
            usleep(pcap_usec_diff - prog_usec_diff);
    }

    /*
     * Build service chaining packet and send it out
     */
    io[0].iov_base = (char *)&default_gre;
    io[0].iov_len = sizeof(struct fe_gre_base);
    io[1].iov_base = (char *)&default_nsh;
    io[1].iov_len = sizeof(struct nsh_hdr);
    io[2].iov_base = (char *)ip_hdr;
    io[2].iov_len = GET_IP_TOTLEN(ip_hdr);

    PRINT_DEBUG("gre %zu, nsh %zu, payload %d\n",sizeof(struct fe_gre_base),
                sizeof(struct nsh_hdr), GET_IP_TOTLEN(ip_hdr));

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = io;
    msg.msg_iovlen = MAX_VECTORS;
    msg.msg_name = &d_addr;
    msg.msg_namelen = sizeof(d_addr);

    tx_bytes = sendmsg(g_sd, &msg, 0);
    if (tx_bytes < 0) {
        perror("sendmsg:");
    }
    g_total_pkts++;
    PRINT_DEBUG("Send %zu bytes\n", tx_bytes);
}

/*
 * Handle usage
 */
static void usage (char *prog) {
    fprintf(stderr, "\n[+] Usage: %s <options>\n", prog);
    fprintf(stderr, "\n+ Options:" );
    fprintf(stderr, "\n\t-f -----------> Send packets fast (no realtime pkt spacing)");
    fprintf(stderr, "\n\t-c <val> -----> PCAP packet count to send");
    fprintf(stderr, "\n\t-i <val> -----> IP address to send to");
    fprintf(stderr, "\n\t-p <val> -----> PCAP File to read from\n\n");
}

/*
 * Main program
 */
int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *pcap_file;
    pcap_t *cnt_handle;

    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }

    /*
     * Handle CLI options
     */
    while (1) {
        char c;

        c = getopt(argc, argv, "fp:c:i:");
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'f':
                g_recreate_real_time = false;
                break;
            case 'p':
                pcap_file = optarg;
                break;
            case 'c':
                g_pkt_cnt = atoi(optarg);
                break;
            case 'i':
                dst_ip_addr = optarg;
                break;
            default:
                fprintf(stderr, "Invalid CLI arg %c\n", c);
                exit (1);
        }
    }

    /*
     * Initialize
     */
    init_nsh_socket();
    printf("Socket initialize.\n");

    /*
     * Open pcap file to replay capture
     */
    pcap_file = strdup(pcap_file);
    g_handle = pcap_open_offline(pcap_file, error_buffer);
    if (g_handle == NULL) {
         fprintf(stderr, "Could not open file %s: %s\n",
                 pcap_file, error_buffer);
         return (-1);
    }

    /*
     * Get pkt count total from capture to create a progress bar
     */
    cnt_handle = pcap_open_offline(pcap_file, error_buffer);
    pcap_loop(cnt_handle, 0, total_packet_cnt, NULL);

    /*
     * Start up packet loop
     */
    printf("Reading %s to send packets from....\n", pcap_file);
    if (g_show_percent) {
        printf("Progress:  0%%");
    } else {
        printf("Pkts sent: %12d", g_total_pkts);
    }
    fflush(stdout);
    pcap_loop(g_handle, 0, packet_handler, NULL);
    printf("\nPacket send finished.\n");

    /*
     * Dump debug stats and what not
     */
    printf("\nSent %d pkts in %s\n", g_total_pkts, pcap_file);
    printf("Elapsed time: %lu.%06lu seconds\n\n",
           ((now_tv.tv_usec >= prog_start_tv.tv_usec) ?
            (now_tv.tv_sec - prog_start_tv.tv_sec) :
            (now_tv.tv_sec - prog_start_tv.tv_sec - 1)),
           ((now_tv.tv_usec >= prog_start_tv.tv_usec) ?
            (now_tv.tv_usec - prog_start_tv.tv_usec) :
            (1000000 + now_tv.tv_usec - prog_start_tv.tv_usec)));

    /*
     * Cleanup
     */
    free(pcap_file);
    pcap_close(g_handle);

    return (0);
}
