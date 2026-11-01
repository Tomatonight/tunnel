/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef TUNNEL_KMOD_UAPI_H
#define TUNNEL_KMOD_UAPI_H
#include <linux/types.h>
#include <linux/ioctl.h>

#define TNLK_ABI 2
#define TNLK_MAX_BLOB (1024U * 1024U)
#define TNLK_MAX_PACKET 65536U
#define TNLK_MAX_NETWORKS 128U
#define TNLK_MAX_PEERS 256U
#define TNLK_MAX_ROUTES 4096U
#define TNLK_MAX_ENDS 256U
#define TNLK_MAX_PREFIXES 4096U
#define TNLK_MAX_HOPS 32U

/* Local ioctl ABI only: integers use native byte order, addresses use network
 * byte order. No pointers except the explicitly aligned blob address. Wire
 * serialization is defined by protocol.cpp forwarding version 2. */
struct tnlk_ip { __u8 family; __u8 bytes[16]; } __attribute__((packed));
/* Endpoint storage is used for both transport peers (port != 0) and virtual
 * node identities in route/session/prefix records (port == 0). */
struct tnlk_endpoint { struct tnlk_ip ip; __u16 port; } __attribute__((packed));
struct tnlk_network { struct tnlk_ip address; __u8 prefix; } __attribute__((packed));
struct tnlk_keys { __u8 id[16]; __u8 send[32]; __u8 receive[32]; };
struct tnlk_create {
    __u32 abi, mtu, transport_mtu, lease_ms;
    struct tnlk_endpoint local, bind;
    char name[16]; /* empty: tnk%d; result contains actual name */
    __u32 ifindex;
} __attribute__((packed));
struct tnlk_blob { __aligned_u64 data; __u32 length; __u32 reserved; };
/* Atomic complete replacement. Arrays follow in the order below. Existing
 * crypto sessions identified by keys.id retain counters/replay windows; a
 * changed key with the same id is rejected. An omitted session is destroyed. */
struct tnlk_snapshot {
    __u32 abi, networks, peers, routes, ends, prefixes;
};
struct tnlk_net {
    struct tnlk_network network;
    struct tnlk_ip local_ip;
} __attribute__((packed));
struct tnlk_peer {
    struct tnlk_endpoint endpoint;
    struct tnlk_keys keys;
    __u8 tcp, ready;
    __u8 networks[TNLK_MAX_NETWORKS / 8]; /* snapshot network index bitmap */
} __attribute__((packed));
struct tnlk_route {
    __u32 network; /* snapshot network index */
    struct tnlk_endpoint destination;
    struct tnlk_ip ip;
    __u32 nhops;
    __u32 hops[TNLK_MAX_HOPS]; /* peer indexes, canonical sorted ECMP order */
} __attribute__((packed));
struct tnlk_end {
    __u32 network;
    struct tnlk_endpoint destination;
    struct tnlk_keys keys;
    __u8 ready;
} __attribute__((packed));
struct tnlk_prefix {
    __u32 network;
    struct tnlk_network prefix;
    struct tnlk_endpoint publisher;
    __u8 selected; /* imported chosen gateway or active local export */
} __attribute__((packed));
struct tnlk_probe {
    struct tnlk_endpoint peer;
    __u64 token;
} __attribute__((packed));
/* read/write preserve packet boundaries; read requires enough space for a
 * complete event. write accepts only TNLK_EVENT_TCP and an encrypted link record.
 * Event queue is bounded; exhaustion drops immediately. No raw IP slow path. */
#define TNLK_EVENT_TCP 1U
#define TNLK_EVENT_NEED_SESSION 2U
#define TNLK_EVENT_PROBE_ACK 3U
#define TNLK_EVENT_REKEY 4U
struct tnlk_event {
    __u32 kind, length; /* payload length, may be zero */
    struct tnlk_endpoint peer; /* next-hop for TCP/ACK, origin for session miss */
    struct tnlk_network network; /* session miss/rekey only */
    __u64 token; /* ACK only */
} __attribute__((packed));
enum tnlk_counter {
    TNLK_TX_PACKETS, TNLK_RX_PACKETS, TNLK_UDP_SENT, TNLK_UDP_RECEIVED,
    TNLK_TCP_SENT, TNLK_TCP_RECEIVED, TNLK_FORWARDED, TNLK_DROPPED,
    TNLK_NO_ROUTE, TNLK_NO_SESSION, TNLK_AUTH_DROP, TNLK_REPLAY_DROP,
    TNLK_MTU_DROP, TNLK_RPF_DROP, TNLK_RESOURCE_DROP, TNLK_SEND_DROP,
    TNLK_POLICY_DROP, TNLK_COUNTER_COUNT
};
struct tnlk_stats { __u64 counters[TNLK_COUNTER_COUNT]; };
#define TNLK_CREATE _IOWR('T', 0x90, struct tnlk_create)
#define TNLK_SNAPSHOT _IOW('T', 0x91, struct tnlk_blob)
#define TNLK_PROBE _IOW('T', 0x92, struct tnlk_probe)
#define TNLK_STATS _IOR('T', 0x93, struct tnlk_stats)
#define TNLK_RENEW _IO('T', 0x94)
#endif
