#ifndef ZMAP_MODULE_SCTP_H
#define ZMAP_MODULE_SCTP_H

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

#ifdef __cplusplus
}
#endif

#endif
