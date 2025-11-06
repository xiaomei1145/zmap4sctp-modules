/* 
 * SCTP 扫描这块
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "validate.h"

// SCTP 协议号
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

// Chunk 类型
#define SCTP_CHUNK_INIT     1
#define SCTP_CHUNK_INIT_ACK 2
#define SCTP_CHUNK_ABORT    6

// 数据包长度
#define SCTP_HEADER_LEN 12
#define SCTP_INIT_CHUNK_LEN 20
#define SCTP_PACKET_LEN (sizeof(struct ether_header) + sizeof(struct ip) + \
                         SCTP_HEADER_LEN + SCTP_INIT_CHUNK_LEN)

// 通用头
struct sctp_header {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t verification_tag;
	uint32_t checksum;
} __attribute__((packed));

struct sctp_chunk_header {
	uint8_t type;
	uint8_t flags;
	uint16_t length;
} __attribute__((packed));

// SCTP INIT Chunk（不含 chunk 头）
struct sctp_init_chunk {
	uint32_t initiate_tag;
	uint32_t a_rwnd;
	uint16_t num_outbound_streams;
	uint16_t num_inbound_streams;
	uint32_t initial_tsn;
} __attribute__((packed));

// CRC32c 查找表
static uint32_t crc32c_table[256];
static bool crc32c_table_initialized = false;

// 初始化
static void init_crc32c_table(void)
{
	uint32_t i, j, crc;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 0; j < 8; j++) {
			if (crc & 1) {
				crc = (crc >> 1) ^ 0x82F63B78;
			} else {
				crc = crc >> 1;
			}
		}
		crc32c_table[i] = crc;
	}
	crc32c_table_initialized = true;
}

// 计算校验和
static uint32_t calculate_crc32c(const uint8_t *buffer, size_t length)
{
	uint32_t crc = 0xFFFFFFFF;
	size_t i;
	
	if (!crc32c_table_initialized) {
		init_crc32c_table();
	}
	
	for (i = 0; i < length; i++) {
		crc = crc32c_table[(crc ^ buffer[i]) & 0xFF] ^ (crc >> 8);
	}
	
	return ~crc;
}

static uint16_t num_source_ports;

static int sctp_global_initialize(struct state_conf *state)
{
	num_source_ports = state->source_port_last - state->source_port_first + 1;

	init_crc32c_table();
	
	log_debug("sctp", "initialized SCTP probe module");
	return EXIT_SUCCESS;
}

static int sctp_prepare_packet(void *buf, macaddr_t *src_mac,
                               macaddr_t *gw_mac, void *arg)
{
	(void)arg;
	
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src_mac, gw_mac);
	
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t ip_len = htons(sizeof(struct ip) + SCTP_HEADER_LEN + 
	                        sizeof(struct sctp_chunk_header) + 
	                        sizeof(struct sctp_init_chunk));
	make_ip_header(ip_header, IPPROTO_SCTP, ip_len);
	
	struct sctp_header *sctp_header = (struct sctp_header *)(&ip_header[1]);
	memset(sctp_header, 0, SCTP_HEADER_LEN);

	struct sctp_chunk_header *chunk_header = 
		(struct sctp_chunk_header *)(&sctp_header[1]);
	chunk_header->type = SCTP_CHUNK_INIT;
	chunk_header->flags = 0;
	chunk_header->length = htons(sizeof(struct sctp_chunk_header) + 
	                             sizeof(struct sctp_init_chunk));
	
	struct sctp_init_chunk *init_chunk = 
		(struct sctp_init_chunk *)(&chunk_header[1]);
	
	// 默认值
	init_chunk->a_rwnd = htonl(106496);
	init_chunk->num_outbound_streams = htons(10);
	init_chunk->num_inbound_streams = htons(65535);
	init_chunk->initial_tsn = htonl(0);
	
	return EXIT_SUCCESS;
}

static int sctp_make_packet(void *buf, size_t *buf_len,
                            ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
                            port_n_t dst_port, uint8_t ttl,
                            uint32_t *validation, int probe_num,
                            uint16_t ip_id, void *arg)
{
	(void)arg;
	
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct sctp_header *sctp_header = (struct sctp_header *)(&ip_header[1]);
	struct sctp_chunk_header *chunk_header = 
		(struct sctp_chunk_header *)(&sctp_header[1]);
	struct sctp_init_chunk *init_chunk = 
		(struct sctp_init_chunk *)(&chunk_header[1]);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;
	ip_header->ip_id = ip_id;
	
	port_h_t sport = get_src_port(num_source_ports, probe_num, validation);
	sctp_header->src_port = htons(sport);
	sctp_header->dst_port = dst_port;
	sctp_header->verification_tag = 0;
	sctp_header->checksum = 0;
	
	init_chunk->initiate_tag = validation[0];
	init_chunk->initial_tsn = validation[1];
	
	size_t sctp_len = SCTP_HEADER_LEN + sizeof(struct sctp_chunk_header) + 
	                  sizeof(struct sctp_init_chunk);
	uint32_t crc = calculate_crc32c((uint8_t *)sctp_header, sctp_len);
	sctp_header->checksum = htonl(crc);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);
	
	*buf_len = SCTP_PACKET_LEN;
	return EXIT_SUCCESS;
}

static void sctp_print_packet(FILE *fp, void *packet)
{
	struct ether_header *eth = (struct ether_header *)packet;
	struct ip *ip = (struct ip *)&eth[1];
	struct sctp_header *sctp = (struct sctp_header *)&ip[1];
	struct sctp_chunk_header *chunk = (struct sctp_chunk_header *)&sctp[1];
	
	fprintf(fp, "SCTP Packet:\n");
	fprintf(fp, "  Source Port: %u\n", ntohs(sctp->src_port));
	fprintf(fp, "  Dest Port: %u\n", ntohs(sctp->dst_port));
	fprintf(fp, "  Verification Tag: 0x%08x\n", ntohl(sctp->verification_tag));
	fprintf(fp, "  Checksum: 0x%08x\n", ntohl(sctp->checksum));
	fprintf(fp, "  Chunk Type: %u\n", chunk->type);
	fprintf(fp, "  Chunk Length: %u\n", ntohs(chunk->length));
	
	fprintf_ip_header(fp, ip);
	fprintf_eth_header(fp, eth);
	fprintf(fp, "------------------------------------------------------\n");
}

static int sctp_validate_packet(const struct ip *ip_hdr, uint32_t len,
                               uint32_t *src_ip, uint32_t *validation,
                               const struct port_conf *ports)
{
	// 验证协议类型
	if (ip_hdr->ip_p != IPPROTO_SCTP) {
		return PACKET_INVALID;
	}
	
	// 验证包长度
	size_t min_len = ip_hdr->ip_hl * 4 + SCTP_HEADER_LEN + 
	                 sizeof(struct sctp_chunk_header);
	if (len < min_len) {
		return PACKET_INVALID;
	}
	
	struct sctp_header *sctp = (struct sctp_header *)((char *)ip_hdr + 
	                                                   ip_hdr->ip_hl * 4);
	struct sctp_chunk_header *chunk = (struct sctp_chunk_header *)(&sctp[1]);
	
	port_h_t sport = ntohs(sctp->src_port);
	port_h_t dport = ntohs(sctp->dst_port);
	
	// 验证源目标端口
	if (!check_src_port(sport, ports)) {
		return PACKET_INVALID;
	}
	
	// 验证目的端口
	if (!check_dst_port(dport, num_source_ports, validation)) {
		return PACKET_INVALID;
	}
	
	// 验证源 IP 在扫描范围内
	if (!blocklist_is_allowed(*src_ip)) {
		return PACKET_INVALID;
	}
	
	// 验证 Chunk 类型（INIT-ACK 或 ABORT）
	if (chunk->type != SCTP_CHUNK_INIT_ACK && chunk->type != SCTP_CHUNK_ABORT) {
		return PACKET_INVALID;
	}
	
	// 验证 Verification Tag
	if (chunk->type == SCTP_CHUNK_INIT_ACK) {
		if (ntohl(sctp->verification_tag) != validation[0]) {
			return PACKET_INVALID;
		}
	}
	
	return PACKET_VALID;
}

static void sctp_process_packet(const u_char *packet, uint32_t len,
                               fieldset_t *fs, uint32_t *validation,
                               const struct timespec ts)
{
	(void)len;
	(void)validation;
	(void)ts;
	
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	struct sctp_header *sctp = (struct sctp_header *)((char *)ip_hdr + 
	                                                   ip_hdr->ip_hl * 4);
	struct sctp_chunk_header *chunk = (struct sctp_chunk_header *)(&sctp[1]);
	
	fs_add_uint64(fs, "sport", (uint64_t)ntohs(sctp->src_port));
	fs_add_uint64(fs, "dport", (uint64_t)ntohs(sctp->dst_port));
	fs_add_uint64(fs, "verification_tag", (uint64_t)ntohl(sctp->verification_tag));

	if (chunk->type == SCTP_CHUNK_INIT_ACK) {
		fs_add_string(fs, "classification", (char *)"init-ack", 0);
		fs_add_bool(fs, "success", 1);

		size_t chunk_data_len = ntohs(chunk->length) - 
		                        sizeof(struct sctp_chunk_header);
		if (chunk_data_len >= sizeof(struct sctp_init_chunk)) {
			struct sctp_init_chunk *init_ack = 
				(struct sctp_init_chunk *)(&chunk[1]);
			
			fs_add_uint64(fs, "initiate_tag", 
			             (uint64_t)ntohl(init_ack->initiate_tag));
			fs_add_uint64(fs, "a_rwnd", 
			             (uint64_t)ntohl(init_ack->a_rwnd));
			fs_add_uint64(fs, "num_outbound_streams", 
			             (uint64_t)ntohs(init_ack->num_outbound_streams));
			fs_add_uint64(fs, "num_inbound_streams", 
			             (uint64_t)ntohs(init_ack->num_inbound_streams));
			fs_add_uint64(fs, "initial_tsn", 
			             (uint64_t)ntohl(init_ack->initial_tsn));
		}
		
	} else if (chunk->type == SCTP_CHUNK_ABORT) {
		fs_add_string(fs, "classification", (char *)"abort", 0);
		fs_add_bool(fs, "success", 0);
		
	} else {
		fs_add_string(fs, "classification", (char *)"other", 0);
		fs_add_bool(fs, "success", 0);
	}
	
	fs_add_uint64(fs, "chunk_type", (uint64_t)chunk->type);
}

static fielddef_t fields[] = {
	{.name = "sport", 
	 .type = "int", 
	 .desc = "SCTP source port"},
	{.name = "dport", 
	 .type = "int", 
	 .desc = "SCTP destination port"},
	{.name = "verification_tag", 
	 .type = "int", 
	 .desc = "SCTP verification tag from response"},
	{.name = "chunk_type", 
	 .type = "int", 
	 .desc = "SCTP chunk type (2=INIT-ACK, 6=ABORT)"},
	{.name = "classification", 
	 .type = "string", 
	 .desc = "Response classification (init-ack, abort, other)"},
	{.name = "success", 
	 .type = "bool", 
	 .desc = "Was SCTP service detected"},
	{.name = "initiate_tag", 
	 .type = "int", 
	 .desc = "Peer's initiate tag from INIT-ACK"},
	{.name = "a_rwnd", 
	 .type = "int", 
	 .desc = "Advertised receiver window credit"},
	{.name = "num_outbound_streams", 
	 .type = "int", 
	 .desc = "Number of outbound streams supported"},
	{.name = "num_inbound_streams", 
	 .type = "int", 
	 .desc = "Number of inbound streams supported"},
	{.name = "initial_tsn", 
	 .type = "int", 
	 .desc = "Initial transmission sequence number"}
};

probe_module_t module_sctp = {
	.name = "sctp",
	.max_packet_length = SCTP_PACKET_LEN,
	.pcap_filter = "sctp || ip proto 132",
	.pcap_snaplen = 256,
	.port_args = 1,
	
	.global_initialize = &sctp_global_initialize,
	.thread_initialize = NULL,
	.prepare_packet = &sctp_prepare_packet,
	.make_packet = &sctp_make_packet,
	.print_packet = &sctp_print_packet,
	.validate_packet = &sctp_validate_packet,
	.process_packet = &sctp_process_packet,
	.close = NULL,
	
	.output_type = OUTPUT_TYPE_STATIC,
	.fields = fields,
	.numfields = sizeof(fields) / sizeof(fields[0]),
	
	.helptext = 
		"Probe module for SCTP. "
		"Sends SCTP INIT packets to SCTP services. "
		"Possible responses:\n"
		"  - INIT-ACK: Service exists and is listening on the port\n"
		"  - ABORT: Port is closed\n"
		"  - No response: Port is filtered or host is down\n\n"
		"Example usage:\n"
		"  zmap -M sctp -p 22 192.168.1.0/24 \n"
		"  zmap -M sctp -p 2905 10.0.0.0/8 \n"
};
