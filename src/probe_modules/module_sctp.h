#ifndef ZMAP_MODULE_SCTP_H
#define ZMAP_MODULE_SCTP_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

// SCTP Chunk 类型常量
#define SCTP_CHUNK_DATA         0
#define SCTP_CHUNK_INIT         1
#define SCTP_CHUNK_INIT_ACK     2
#define SCTP_CHUNK_SACK         3
#define SCTP_CHUNK_HEARTBEAT    4
#define SCTP_CHUNK_HEARTBEAT_ACK 5
#define SCTP_CHUNK_ABORT        6
#define SCTP_CHUNK_SHUTDOWN     7
#define SCTP_CHUNK_SHUTDOWN_ACK 8
#define SCTP_CHUNK_ERROR        9
#define SCTP_CHUNK_COOKIE_ECHO  10
#define SCTP_CHUNK_COOKIE_ACK   11
#define SCTP_CHUNK_SHUTDOWN_COMPLETE 14

// SCTP 协议头
struct sctp_header {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t verification_tag;
	uint32_t checksum;
} __attribute__((packed));

// SCTP Chunk 头
struct sctp_chunk_header {
	uint8_t type;
	uint8_t flags;
	uint16_t length;
} __attribute__((packed));

// SCTP INIT Chunk
struct sctp_init_chunk {
	uint32_t initiate_tag;
	uint32_t a_rwnd;
	uint16_t num_outbound_streams;
	uint16_t num_inbound_streams;
	uint32_t initial_tsn;
} __attribute__((packed));

// SCTP 参数头
struct sctp_param_header {
	uint16_t type;
	uint16_t length;
} __attribute__((packed));

// Supported Address Types
struct sctp_param_supported_addr_types {
	struct sctp_param_header header;  // type=0x000c
	uint16_t addr_type_1;
	uint16_t padding;
} __attribute__((packed));

// ECN, Forward TSN
struct sctp_param_simple {
	struct sctp_param_header header;
} __attribute__((packed));

// INIT
struct sctp_init_with_params {
	struct sctp_init_chunk init;
	struct sctp_param_supported_addr_types addr_types;
	struct sctp_param_simple ecn;
	struct sctp_param_simple forward_tsn;
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif // ZMAP_MODULE_SCTP_H
