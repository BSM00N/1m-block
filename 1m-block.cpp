
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>      /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string.h>
#include <string>
#include <set>

#include "header.h"


//해당부분의 경우에는 과목26시간에 사용한 코드를 사용하였다. 
clock_t elapsed;
float   sec;
#define START_TIME \
{\
    elapsed = -clock();\
}
#define STOP_TIME \
{\
    elapsed += clock();\
   sec = (float)elapsed/CLOCKS_PER_SEC;\
}
#define PRINT_TIME(str) \
{\
    printf("\n[%-15s: %.5f s]",str,sec);\
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
   int id = 0;
   struct nfqnl_msg_packet_hdr *ph;
   struct nfqnl_msg_packet_hw *hwph;
   uint32_t mark, ifi, uid, gid;
   int ret;
   unsigned char *data, *secdata;

   ph = nfq_get_msg_packet_hdr(tb);
   if (ph) {
      id = ntohl(ph->packet_id);
      printf("hw_protocol=0x%04x hook=%u id=%u ",
         ntohs(ph->hw_protocol), ph->hook, id);
   }

   hwph = nfq_get_packet_hw(tb);
   if (hwph) {
      int i, hlen = ntohs(hwph->hw_addrlen);

      printf("hw_src_addr=");
      for (i = 0; i < hlen-1; i++)
         printf("%02x:", hwph->hw_addr[i]);
      printf("%02x ", hwph->hw_addr[hlen-1]);
   }

   mark = nfq_get_nfmark(tb);
   if (mark)
      printf("mark=%u ", mark);

   ifi = nfq_get_indev(tb);
   if (ifi)
      printf("indev=%u ", ifi);

   ifi = nfq_get_outdev(tb);
   if (ifi)
      printf("outdev=%u ", ifi);
   ifi = nfq_get_physindev(tb);
   if (ifi)
      printf("physindev=%u ", ifi);

   ifi = nfq_get_physoutdev(tb);
   if (ifi)
      printf("physoutdev=%u ", ifi);

   if (nfq_get_uid(tb, &uid))
      printf("uid=%u ", uid);

   if (nfq_get_gid(tb, &gid))
      printf("gid=%u ", gid);

   ret = nfq_get_secctx(tb, &secdata);
   if (ret > 0)
      printf("secctx=\"%.*s\" ", ret, secdata);

   ret = nfq_get_payload(tb, &data);
   if (ret >= 0)
      printf("payload_len=%d ", ret);

   fputc('\n', stdout);

   return id;
}

int num;
std::set<std::string> host;
   
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
         struct nfq_data *nfa, void *data)
{
    uint32_t id = print_pkt(nfa);
    printf("entering callback\n");

    unsigned char *pkt_d;
    int temp = nfq_get_payload(nfa, &pkt_d);
    const char *site_name = NULL;

    //IP 파싱
    IpHdr *iphdr = (IpHdr *)pkt_d;
    //Protocol 내에서 header가 TCP:0x06가 아니라면 받아옴 
    if (iphdr->protocol != 0x06) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }


    //TCP 파싱
    TcpHdr *tcphdr = (TcpHdr *)(pkt_d + sizeof(IpHdr));
    //HTTP 파싱
    const char *httphdr = (const char *)(pkt_d + sizeof(IpHdr) + (tcphdr->offset * 4));

    if ((ntohs(tcphdr->d_port) == 80) && (strncmp(httphdr, "GET", 3) == 0) && ((site_name = strstr(httphdr, "Host: ")) != NULL)) {
        

        // "Host: " 문자열을 찾은 경우에만 처리
        if (site_name != NULL) {
            START_TIME;
            // "Host: " 문자열을 찾은 위치에서 6바이트 뒤부터 시작하는 부분 문자열을 추출하여 site_str에 저장
            std::string site_str(site_name + 6);
            std::istringstream site_stream(site_str);
            
            // 문자열에서 '\r'을 기준으로 구분하여 site_str을 다시 설정
            getline(site_stream, site_str, '\r');

            // 추출된 호스트명이 차단 목록에 있는지 확인
            if (host.find(site_str) != host.end()) {
                std::cout << site_str << " Blocked\n\n";
                STOP_TIME;
                PRINT_TIME("Search Block Site");
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
            STOP_TIME;
        }

        }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv){
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    uint32_t queue = 0;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        printf("syntax error : using as 1m-block top-1m.csv\n");
        return 0;
    }

    num = argc;

    std::ifstream file(argv[1]);
        if (!file.is_open()) {
            std::cout << "No such " << argv[1] << " file\n";
            return 0;
        }


        //csv파일의 경우 각 행이 , 로 구분되어 있는데 이 부분에서 사이트만 받아오는 코드
        while (!file.eof()) {
            std::string line1, line2;
            std::getline(file, line1, ',');
            std::getline(file, line2, '\n');
            host.insert(line2);
        }

        file.close();

        printf("Finish to Open a file\n");

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    printf("setting flags to request UID and GID\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
        fprintf(stderr, "This kernel version does not allow to "
                "retrieve process UID/GID.\n");
    }

    printf("setting flags to request security context\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
        fprintf(stderr, "This kernel version does not allow to "
                "retrieve security context.\n");
    }

    printf("Waiting for packets...\n");

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
        * are sent from kernel-space, the socket buffer that we use
        * to enqueue packets may fill up returning ENOBUFS. Depending
        * on your application, this error may be ignored. Please, see
        * the doxygen documentation of this library on how to improve
        * this situation.
        */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    #ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
        * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
    #endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}