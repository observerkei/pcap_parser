#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <error.h>

#include "pcapparser.h"

#define  PCAP_FILE_MAGIC_1   0Xd4
#define  PCAP_FILE_MAGIC_2   0Xc3
#define  PCAP_FILE_MAGIC_3   0Xb2
#define  PCAP_FILE_MAGIC_4   0Xa1

#define IP2			"\2\0\0\0"
#define IP2_LEN		4
#define LOOPBACK	4
#define ETHERNET	14

#define SKB_TO_SERVER	1
#define SKB_TO_CLIENT	2

#define is_print(ch) ((('a' <= (ch)) && ((ch) <= 'z')) \
		|| (('A' <= (ch)) && ((ch) <= 'Z')) \
		|| (('0' <= (ch)) && ((ch) <= '9')))

#define pcap_parser_dbg(fmt, arg...) \
	{\
		if (g_pcap_parser_dbg_enable)  \
		{ \
			fprintf(stderr, fmt, ##arg); \
		} \
	}

/*pcap file header*/
typedef struct pcap_file_header_st {
    uint8_t   magic[4];
    uint16_t   version_major;
    uint16_t   version_minor;
    int32_t    thiszone;      /*时区修正*/
    uint32_t   sigfigs;       /*精确时间戳*/
    uint32_t   snaplen;       /*抓包最大长度*/
    uint32_t   linktype;      /*链路类型*/
} pcap_file_header_t;

/*pcap packet header*/
typedef struct pcap_pkthdr_st {
    uint32_t   seconds;     /*秒数*/
    uint32_t   u_seconds;   /*毫秒数*/
    uint32_t   caplen;      /*数据包长度*/
    uint32_t   len;         /*文件数据包长度*/
	uint8_t    data[0];
} pcap_pkthdr_t;

typedef struct {
	size_t count;
	uint8_t *buf;
} fpcap_t;

typedef struct {
	size_t count;
	pcap_pkthdr_t *hdr[0];
} pkt_t;

typedef struct msg_st {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint16_t payload_len;
	union {
		uint8_t flag;
		struct {
			uint8_t fin:1,
				syn:1,
				rst:1,
				psh:1,
				ack:1,
				urg:1,
				ece:1,
				cwr:1;
		};
	};
	const uint8_t *payload_data;
} msg_t;

typedef struct tcp_st {
	size_t count;
	msg_t msg[0];
} tcp_t;

static fpcap_t s_fpcap = {0};
static pkt_t *s_pkt = NULL;
static tcp_t *s_tcp = NULL;

char g_pcap_parser_dbg_enable = 1;

static int pcap_read(const char *fname, fpcap_t *fpcap)
{
	if (!fname || !fpcap) {
		return -1;
	}
	FILE *m_fp = fopen(fname, "r");
	if (NULL == m_fp) {
		perror("fail to open");
		return -1;
	}
	fseek(m_fp, 0L,SEEK_END);
	fpcap->count = ftell(m_fp);
	size_t ret = 0;
	fseek(m_fp, 0L,SEEK_SET);

	fpcap->buf = (uint8_t *)malloc(fpcap->count);
	if (NULL == fpcap->buf) {
		fclose(m_fp);
		perror("fail to malloc");
		return -1;
	}

	ret = fread(fpcap->buf, sizeof(char), fpcap->count, m_fp);
	if (fpcap->count != ret) {
		free(fpcap->buf);
		fpcap->buf = NULL;
		fclose(m_fp);
		perror("fail to fread");
		return -1;
	}
	fclose(m_fp);

	return 0;
}

static int pcap_parser_hdr(const fpcap_t *fpcap, pkt_t **pkt)
{
	if (!fpcap || !pkt || *pkt) {
		return -1;
	}
	size_t i = 0;
	size_t recort_count = 0;
	size_t pkthdr_count = 0;
	pcap_pkthdr_t *p_pcap_pkthdr = NULL;

	for (recort_count = sizeof(pcap_file_header_t);
			recort_count < fpcap->count;) {
		p_pcap_pkthdr = (pcap_pkthdr_t *)(fpcap->buf + recort_count);
		++pkthdr_count;
		recort_count += sizeof(pcap_pkthdr_t) + p_pcap_pkthdr->caplen;				
	}

	*pkt = (pkt_t *)malloc(sizeof(pkt_t) + pkthdr_count*sizeof(pcap_pkthdr_t **));
	if (NULL == *pkt) {
		perror("fail to malloc");
		return -1;
	}
	memset(*pkt, 0, sizeof(pkt_t) + pkthdr_count*sizeof(pcap_pkthdr_t **));

	(*pkt)->count = pkthdr_count;

	for (i = 0, recort_count = sizeof(pcap_file_header_t); 
			i < (*pkt)->count; ++i) {
		(*pkt)->hdr[i] = (pcap_pkthdr_t *)(fpcap->buf + recort_count);
		recort_count += sizeof(pcap_pkthdr_t) + (*pkt)->hdr[i]->caplen;
	}

	return 0;
}

static int hdr_parser_tcp(const pkt_t *pkt, tcp_t **tcp) 
{
	if (!pkt || !tcp || *tcp) {
		return -1;
	}
	size_t i = 0, j = 0;

	*tcp = (tcp_t *)malloc(sizeof(tcp_t) + pkt->count * sizeof(msg_t));
	if (NULL == tcp) {
		perror("fail to malloc");
		return -1;
	}
	memset(*tcp, 0, sizeof(tcp_t) + pkt->count * sizeof(msg_t));
	(*tcp)->count = pkt->count;


	for (i = 0; i < pkt->count; ++i) {	
		pcap_parser_dbg("[%4lu] ", i+1);

		uint8_t ethernet_len = ETHERNET;
		uint8_t ip_version = ((pkt->hdr[i]->data[4])&0xF0);
		uint16_t type = ntohs(*(uint16_t *)(&pkt->hdr[i]->data[12]));

		if (!memcmp(pkt->hdr[i]->data, IP2, IP2_LEN) && (0x40 == ip_version)) {
			pcap_parser_dbg("Loopback ");
			ethernet_len = LOOPBACK;
		} else if (0x0800 == type) {
			pcap_parser_dbg("Ethernet ");
			ethernet_len = ETHERNET;
		} else if (0x0806 == type) {
			pcap_parser_dbg("ARP \n");
			continue;
		} else {	
			pcap_parser_dbg("parser fail (%x) \n", type);
			continue;
		}
		uint16_t iph_len = ((pkt->hdr[i]->data[ethernet_len])&0x0F)*4;
		uint32_t tcp_offset = ethernet_len + iph_len;
		uint16_t tcph_len = (((pkt->hdr[i]->data + tcp_offset)[12]&0xF0)>>4)*4;
		uint32_t payload_offset = tcp_offset + tcph_len;

		uint32_t payload_len  = pkt->hdr[i]->len  - payload_offset;
		uint8_t *payload_data = pkt->hdr[i]->data + payload_offset;

		uint32_t sip   = *(uint32_t *)(pkt->hdr[i]->data + tcp_offset - sizeof(uint32_t)*2);
		uint32_t dip   = *(uint32_t *)(pkt->hdr[i]->data + tcp_offset - sizeof(uint32_t));
		uint16_t sport = *(uint16_t *)(pkt->hdr[i]->data + tcp_offset);
		uint16_t dport = *(uint16_t *)(pkt->hdr[i]->data + tcp_offset + sizeof(uint16_t));

		(*tcp)->msg[i].sip = sip;
		(*tcp)->msg[i].dip = dip;
		(*tcp)->msg[i].sport = ntohs(sport);
		(*tcp)->msg[i].dport = ntohs(dport);

		(*tcp)->msg[i].flag = (pkt->hdr[i]->data + tcp_offset)[13];

		(*tcp)->msg[i].payload_len  = payload_len;
		(*tcp)->msg[i].payload_data = payload_data;

		pcap_parser_dbg("sip:%08x, dip:%08x, sport:%5u, dport:%5u, ", sip, dip, ntohs(sport), ntohs(dport));

		pcap_parser_dbg("cwr:%u, ece:%u, urg:%u, ack:%u, psh:%u, rst:%u, syn:%u, fin:%u, ",
				(*tcp)->msg[i].cwr, (*tcp)->msg[i].ece, (*tcp)->msg[i].urg, (*tcp)->msg[i].ack, 
				(*tcp)->msg[i].psh, (*tcp)->msg[i].rst, (*tcp)->msg[i].syn, (*tcp)->msg[i].fin);

		pcap_parser_dbg("payload_len:%4u, payload_data:", payload_len);
		for (j = 0; j < payload_len; ++j) {
			if (j > 20) {
				break;
			}
			pcap_parser_dbg(" %c", is_print(payload_data[j]) ? payload_data[j] : '.');
		}
		pcap_parser_dbg("\n");
	}

	return 0;
}

static void pcap_reader_destory(void)
{
	if (s_fpcap.buf) {
		free(s_fpcap.buf);
		s_fpcap.buf = NULL;
	}
	if (s_pkt) {
		free(s_pkt);
		s_pkt = NULL;
	}
	if (s_tcp) {
		free(s_tcp);
		s_tcp = NULL;
	}
}

static int pcap_reader_create(const char *fname) 
{
	if (!fname) {
		pcap_parser_dbg("NULL == fname\n");
		return -1;		
	}
	if (pcap_read(fname, &s_fpcap)) {
		return -1;
	}
	if (pcap_parser_hdr(&s_fpcap, &s_pkt)) {
		return -1;
	}
	if (hdr_parser_tcp(s_pkt, &s_tcp)) {
		return -1;
	}

	return 0;
}

static int port_to_dir(uint16_t sport, uint16_t dport)
{
	static int flag = 0;
	static uint16_t private_sport = 0;
	static uint16_t private_dport = 0;

	if (!flag) {
		flag = ~flag;
		private_sport = sport;
		private_dport = dport;
	} else if (!((sport == private_sport && dport == private_sport)
			|| (dport == private_sport && sport == private_dport))) {
		private_sport = sport;
		private_dport = dport;
	}

	if (sport == private_sport) {
		return SKB_TO_SERVER;
	} else if (dport == private_sport) {
		return SKB_TO_CLIENT;
	} else {
		return -1;
	}
}

static int tcp_parser_docker(const char *tcp_arg, parser_docker_t hook, char *hook_hdr)
{
	if (tcp_arg == NULL || hook == NULL) {
		return -1;
	}
	const tcp_t *tcp = (const tcp_t *)tcp_arg;
	int i = 0;
	for (i = 0; i < tcp->count; ++i) {
		if (hook(hook_hdr, tcp->msg[i].payload_data, tcp->msg[i].payload_len,
					port_to_dir(tcp->msg[i].sport, tcp->msg[i].dport))) {
			return -1;
		}
	}

	return 0;
}

int pcap_parser(const char *pcap_file, parser_docker_t hook, char *hook_hdr)
{
	if (NULL == pcap_file) {
		pcap_parser_dbg("use ./app pcap_filename\n");
		return -1;
	}

	if (pcap_reader_create(pcap_file)) {
		goto out;
	}

	if (tcp_parser_docker((const char *)s_tcp, hook, hook_hdr)) {
		goto out;
	}

out:
	pcap_reader_destory();

	return 0;
}

