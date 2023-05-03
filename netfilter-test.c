#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "libnet.h"
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char *host;

void usage() {
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test test.gilgil.net\n");
}

int is_http_packet(char*packet) {
    // Check if packet starts with an HTTP method
    static const char* methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT","PATCH"};
    for (int i = 0; i < 9; i++) {
        size_t method_len = strlen(methods[i]);
        if (memcmp(packet, methods[i], method_len) == 0) {
            return 1;
        }
    }
    return 0;
}


int check_dangerous_site(struct nfq_data *tb){
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *data;
	int drop_check=NF_ACCEPT;
	
	ph = nfq_get_msg_packet_hdr(tb);
	if (ntohs(ph->hw_protocol) != ETHERTYPE_IP){
		return drop_check;
	}
	int data_size = 0;
	data_size = nfq_get_payload(tb, &data);
	if (data_size<0){
		return drop_check;
	}
	
	int data_idx=0;
	struct libnet_ipv4_hdr* ip_header;
	ip_header = (struct libnet_ipv4_hdr*) data;
	data_idx += ip_header->ip_hl * 4;
	
	struct libnet_tcp_hdr* tcp_header;
	tcp_header = (struct libnet_tcp_hdr*)(data+data_idx);
	data_idx += tcp_header->th_off * 4;
	
	if (ip_header->ip_p == TCP_PROTOCOL){
		if(ntohs(tcp_header->th_dport) == http_port ){
			char* http_header;
			http_header = (data+data_idx);
			if(is_http_packet(http_header)){
				if (strstr(http_header,host)!=NULL){
					printf("!!dangerous site filtered!!!\n");
					drop_check=NF_DROP;
				}
				
			}

		}
	
	}
	return drop_check;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	int id = 0;
	int drop_check=NF_ACCEPT;
	
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	drop_check=check_dangerous_site(nfa);
	return nfq_set_verdict(qh, id, drop_check, 0, NULL);
}

int main(int argc, char **argv)
{
	if(argc !=2) {
		usage();
		return -1;
	}
	
	host = argv[1];
	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

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

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
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