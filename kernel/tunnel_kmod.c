// SPDX-License-Identifier: GPL-2.0-only
/* Optional layer-3 tunnel backend. All UDP plaintext and ciphertext processing
 * stays in the kernel. The owning file controls lifetime and a renewable lease;
 * closing it removes the device, socket, sessions and return-flow permissions.
 *
 * The datapath never waits for a key, allocation or socket send space. A single
 * per-instance BH lock owns sequence numbers and replay windows. Only synchronous
 * AEAD implementations are selected. No packet is queued waiting for a session.
 */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/ratelimit.h>
#include <linux/rtnetlink.h>
#include <linux/nsproxy.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <net/net_namespace.h>
#include <net/udp_tunnel.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ipv6_stubs.h>
#include "tunnel_uapi.h"
#include "tunnel_wire.h"

#define TK_FLOW_LIMIT 1024
#define TK_EVENT_LIMIT 512
#define TK_EVENT_BYTES (512 * 1024)

struct tk_crypto {
	struct crypto_aead *send, *receive;
	u64 next, highest, window;
};
struct tk_state {
	void *blob;
	struct tnlk_snapshot *header;
	struct tnlk_net *nets;
	struct tnlk_peer *peers;
	struct tnlk_route *routes;
	struct tnlk_end *ends;
	struct tnlk_prefix *prefixes;
	struct tk_crypto **link_crypto, **end_crypto;
};
struct tk_tuple {
	struct tnlk_network network;
	struct tnlk_ip source, destination;
	u8 protocol;
	u16 source_port, destination_port;
};
struct tk_flow {
	struct tk_tuple key;
	struct tnlk_endpoint peer;
	unsigned long expires;
	u32 lifetime;
};
struct tk_fragment_key {
	struct tnlk_network network;
	struct tnlk_ip source, destination;
	u8 protocol, id_size, id[4];
};
struct tk_fragment {
	struct tk_fragment_key key;
	struct tk_tuple flow;
	unsigned long expires;
	bool reply;
};
struct tk_packet {
	struct tnlk_ip source, destination;
	u8 protocol, fragment_protocol, kind;
	u32 offset;
	bool fragmented, later;
	u8 id_size, id[4];
	u64 flow;
};
struct tk {
	struct mutex control, reader;
	spinlock_t lock;
	struct net *net;
	struct net_device *dev;
	struct socket *udp;
	struct tnlk_create config;
	struct tk_state *state;
	struct tk_flow *flows;
	struct tk_fragment *fragments;
	struct sk_buff_head events;
	wait_queue_head_t wait;
	atomic_t event_bytes;
	struct ratelimit_state notifications;
	struct tnlk_stats stats;
	unsigned long deadline;
	bool closing;
};

static bool tk_ip_equal(const struct tnlk_ip *a, const struct tnlk_ip *b)
{ return !memcmp(a, b, sizeof(*a)); }
static bool tk_endpoint_equal(const struct tnlk_endpoint *a, const struct tnlk_endpoint *b)
{ return !memcmp(a, b, sizeof(*a)); }
static bool tk_network_equal(const struct tnlk_network *a, const struct tnlk_network *b)
{ return !memcmp(a, b, sizeof(*a)); }
static bool tk_ip_valid(const struct tnlk_ip *ip)
{
	static const u8 zero[16];
	static const u8 mapped[12] = {0,0,0,0,0,0,0,0,0,0,255,255};
	return (ip->family == 4 && !memcmp(ip->bytes + 4, zero, 12)) ||
		(ip->family == 6 && memcmp(ip->bytes, mapped, 12));
}
static bool tk_multicast(const struct tnlk_ip *ip)
{ return ip->family == 4 ? (ip->bytes[0] & 0xf0) == 0xe0 : ip->bytes[0] == 0xff; }
static bool tk_unicast(const struct tnlk_ip *ip)
{
	static const u8 zero[16];
	return tk_ip_valid(ip) && memcmp(ip->bytes, zero, 16) && !tk_multicast(ip) &&
		!(ip->family == 4 && (!ip->bytes[0] || ip->bytes[0] >= 240));
}
static bool tk_endpoint_valid(const struct tnlk_endpoint *e)
{ return e->port && tk_unicast(&e->ip); }
/* Virtual node identities share the endpoint storage in the local ABI, but
 * deliberately carry no transport port.  Transport peers continue to use
 * tk_endpoint_valid above. */
static bool tk_node_valid(const struct tnlk_endpoint *e)
{ return !e->port && tk_unicast(&e->ip); }
static bool tk_node_equal(const struct tnlk_endpoint *a, const struct tnlk_endpoint *b)
{ return !memcmp(&a->ip, &b->ip, sizeof(a->ip)); }
static bool tk_contains(const struct tnlk_network *n, const struct tnlk_ip *ip)
{
	u32 bytes = n->prefix / 8, bits = n->prefix % 8;
	return n->address.family == ip->family &&
		!memcmp(n->address.bytes, ip->bytes, bytes) &&
		(!bits || !((n->address.bytes[bytes] ^ ip->bytes[bytes]) & (0xff << (8 - bits))));
}
static bool tk_network_valid(const struct tnlk_network *n)
{
	u32 i;
	if (!tk_ip_valid(&n->address) || n->prefix > (n->address.family == 4 ? 32 : 128)) return false;
	for (i = n->prefix; i < 128; ++i)
		if (n->address.bytes[i / 8] & (1 << (7 - i % 8))) return false;
	return true;
}
static bool tk_broadcast(const struct tnlk_network *n, const struct tnlk_ip *ip)
{
	u32 i;
	if (ip->family != 4) return false;
	if (ip->bytes[0] == 255 && ip->bytes[1] == 255 && ip->bytes[2] == 255 && ip->bytes[3] == 255) return true;
	if (n->prefix >= 31 || !tk_contains(n, ip)) return false;
	for (i = n->prefix; i < 32; ++i)
		if (!(ip->bytes[i / 8] & (1 << (7 - i % 8)))) return false;
	return true;
}
static bool tk_host(const struct tnlk_network *n, const struct tnlk_ip *ip)
{
	return tk_contains(n, ip) && tk_unicast(ip) &&
		!(ip->family == 4 && n->prefix < 31 && (tk_ip_equal(&n->address, ip) || tk_broadcast(n, ip)));
}
static void tk_drop(struct tk *t, enum tnlk_counter why)
{
	t->stats.counters[TNLK_DROPPED]++;
	t->stats.counters[why]++;
	if (t->dev) t->dev->stats.tx_dropped++;
}
static bool tk_live(struct tk *t)
{ return !t->closing && t->state && time_before(jiffies, t->deadline); }
static bool tk_unexpired(unsigned long expires)
{ return expires && time_before(jiffies, expires); }

static void tk_crypto_free(struct tk_crypto *c)
{
	if (!c) return;
	if (c->send) crypto_free_aead(c->send);
	if (c->receive) crypto_free_aead(c->receive);
	kfree_sensitive(c);
}
static struct tk_crypto *tk_crypto_new(const struct tnlk_keys *keys)
{
	struct tk_crypto *c = kzalloc(sizeof(*c), GFP_KERNEL);
	int error;
	if (!c) return ERR_PTR(-ENOMEM);
	c->send = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(c->send)) { error = PTR_ERR(c->send); c->send = NULL; goto fail; }
	c->receive = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(c->receive)) { error = PTR_ERR(c->receive); c->receive = NULL; goto fail; }
	error = crypto_aead_setkey(c->send, keys->send, 32);
	if (!error) error = crypto_aead_setkey(c->receive, keys->receive, 32);
	if (!error) error = crypto_aead_setauthsize(c->send, 16);
	if (!error) error = crypto_aead_setauthsize(c->receive, 16);
	if (error) goto fail;
	c->next = 1;
	return c;
fail:
	tk_crypto_free(c);
	return ERR_PTR(error);
}

/* AAD is record header followed by the immutable forwarding-header prefix.
 * The temporary contiguous scatterlist avoids relying on stack scatterlist
 * lifetime and exactly reproduces OpenSSL's two AAD updates. */
static int tk_crypt(struct crypto_aead *tfm, u8 *record, u32 plain_len,
		    const u8 *aad, u32 aad_len, bool encrypt)
{
	struct aead_request *req;
	struct scatterlist sg;
	u32 auth = TK_RECORD_HEADER + aad_len, bytes = auth + plain_len + 16;
	u8 nonce[12] = {0}, *work;
	int error;
	work = kmalloc(bytes, GFP_ATOMIC);
	if (!work) return -ENOMEM;
	req = aead_request_alloc(tfm, GFP_ATOMIC);
	if (!req) { kfree_sensitive(work); return -ENOMEM; }
	memcpy(work, record, TK_RECORD_HEADER);
	if (aad_len) memcpy(work + TK_RECORD_HEADER, aad, aad_len);
	memcpy(work + auth, record + TK_RECORD_HEADER, plain_len + (encrypt ? 0 : 16));
	memcpy(nonce + 4, record + 24, 8);
	sg_init_one(&sg, work, bytes);
	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, auth);
	aead_request_set_crypt(req, &sg, &sg, plain_len + (encrypt ? 0 : 16), nonce);
	error = encrypt ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req);
	if (!error) memcpy(record + TK_RECORD_HEADER, work + auth, plain_len + (encrypt ? 16 : 0));
	aead_request_free(req);
	kfree_sensitive(work);
	return error;
}
static int tk_seal(struct tk_crypto *c, const struct tnlk_keys *keys, u8 scope,
		   u8 *record, u32 size, const u8 *aad, u32 aad_len)
{
	if (!c || size > 65535 || c->next >= (1ULL << 32)) return -EKEYEXPIRED;
	memcpy(record, "TNL1", 4); record[4] = 1; record[5] = scope;
	tw_put16(record + 6, size); memcpy(record + 8, keys->id, 16);
	tw_put64(record + 24, c->next++);
	return tk_crypt(c->send, record, size, aad, aad_len, true);
}
static int tk_open_record(struct tk_crypto *c, const struct tnlk_keys *keys, u8 scope,
			  u8 *record, u32 size, const u8 *aad, u32 aad_len)
{
	u64 sequence, delta;
	u32 plain;
	int error;
	if (!c || size < TK_RECORD_OVERHEAD || memcmp(record, "TNL1", 4) ||
	    record[4] != 1 || record[5] != scope || memcmp(record + 8, keys->id, 16)) return -EBADMSG;
	plain = tw_get16(record + 6);
	if (size != plain + TK_RECORD_OVERHEAD) return -EBADMSG;
	sequence = tw_get64(record + 24);
	if (!sequence || sequence >= (1ULL << 32)) return -EBADMSG;
	if (sequence <= c->highest) {
		delta = c->highest - sequence;
		if (delta >= 64 || (c->window & (1ULL << delta))) return -EALREADY;
	}
	error = tk_crypt(c->receive, record, plain, aad, aad_len, false);
	if (error) return error;
	if (sequence > c->highest) {
		delta = sequence - c->highest;
		c->window = delta >= 64 ? 1 : (c->window << delta) | 1;
		c->highest = sequence;
	} else c->window |= 1ULL << (c->highest - sequence);
	return plain;
}

static bool tk_event(struct tk *t, u32 kind, const struct tnlk_endpoint *peer,
		     const struct tnlk_network *network, u64 token, const u8 *data, u32 length)
{
	struct sk_buff *skb;
	struct tnlk_event *event;
	u32 size = sizeof(*event) + length;
	if (skb_queue_len(&t->events) >= TK_EVENT_LIMIT || atomic_read(&t->event_bytes) + size > TK_EVENT_BYTES)
		return false;
	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb) return false;
	event = (struct tnlk_event *)skb_put(skb, sizeof(*event));
	memset(event, 0, sizeof(*event));
	event->kind = kind; event->length = length;
	if (peer) event->peer = *peer;
	if (network) event->network = *network;
	event->token = token;
	if (length) memcpy(skb_put(skb, length), data, length);
	atomic_add(size, &t->event_bytes);
	skb_queue_tail(&t->events, skb);
	wake_up_interruptible(&t->wait);
	return true;
}

static struct tnlk_route *tk_route(struct tk_state *s, u32 network, const struct tnlk_endpoint *e)
{
	u32 i;
	for (i = 0; i < s->header->routes; ++i)
		if (s->routes[i].network == network && tk_node_equal(&s->routes[i].destination, e)) return &s->routes[i];
	return NULL;
}
static struct tnlk_route *tk_route_ip(struct tk_state *s, u32 network, const struct tnlk_ip *ip)
{
	u32 i;
	for (i = 0; i < s->header->routes; ++i)
		if (s->routes[i].network == network && tk_ip_equal(&s->routes[i].ip, ip)) return &s->routes[i];
	return NULL;
}
static int tk_next(struct tk_state *s, struct tnlk_route *route, u64 flow)
{
	u32 selected;
	if (!route || !route->nhops) return -1;
	flow ^= flow >> 30; flow *= 0xbf58476d1ce4e5b9ULL;
	flow ^= flow >> 27; flow *= 0x94d049bb133111ebULL; flow ^= flow >> 31;
	selected = route->hops[flow % route->nhops];
	return s->peers[selected].ready ? selected : -1;
}
static bool tk_published(struct tk_state *s, u32 network, const struct tnlk_endpoint *publisher,
			 const struct tnlk_ip *ip, bool selected)
{
	u32 i;
	for (i = 0; i < s->header->prefixes; ++i) {
		const struct tnlk_prefix *p = &s->prefixes[i];
		if (p->network == network && (!selected || p->selected) && tk_node_equal(&p->publisher, publisher) &&
		    tk_host(&p->prefix, ip)) return true;
	}
	return false;
}
static struct tnlk_endpoint *tk_gateway(struct tk_state *s, u32 network, const struct tnlk_ip *ip)
{
	struct tnlk_prefix *best = NULL;
	u32 i;
	for (i = 0; i < s->header->prefixes; ++i) {
		struct tnlk_prefix *p = &s->prefixes[i];
		if (p->network == network && p->selected && tk_host(&p->prefix, ip) &&
		    tk_route(s, network, &p->publisher) && (!best || p->prefix.prefix > best->prefix.prefix)) best = p;
	}
	return best ? &best->publisher : NULL;
}

/* Packet inspection matches tunnel.cpp, including fragment ECMP affinity. */
static bool tk_parse(const u8 *data, u32 size, struct tk_packet *p, bool quoted)
{
	u32 version, count;
	bool seen = false;
	u8 hash_protocol;
	memset(p, 0, sizeof(*p));
	if (size < 20) return false;
	version = data[0] >> 4;
	p->source.family = p->destination.family = version;
	if (version == 4) {
		u16 frag = tw_get16(data + 6), length = tw_get16(data + 2);
		p->offset = (data[0] & 15) * 4;
		if (p->offset < 20 || p->offset > size || length < p->offset || (!quoted && length != size)) return false;
		memcpy(p->source.bytes, data + 12, 4); memcpy(p->destination.bytes, data + 16, 4);
		p->protocol = data[9]; p->fragment_protocol = p->protocol;
		p->fragmented = !!(frag & 0x3fff); p->later = !!(frag & 0x1fff);
		p->id_size = 2; memcpy(p->id, data + 4, 2);
		hash_protocol = p->protocol;
	} else if (version == 6) {
		if (size < 40 || (!quoted && 40U + tw_get16(data + 4) != size)) return false;
		memcpy(p->source.bytes, data + 8, 16); memcpy(p->destination.bytes, data + 24, 16);
		p->protocol = data[6]; p->offset = 40; hash_protocol = p->protocol;
		for (count = 0; count < 16; ++count) {
			u32 length;
			if (p->protocol == 44) {
				u16 frag;
				if (seen || p->offset + 8 > size) return false;
				seen = true; frag = tw_get16(data + p->offset + 2);
				p->fragmented = !!(frag & 0xfff9); p->later = !!(frag & 0xfff8);
				p->id_size = 4; memcpy(p->id, data + p->offset + 4, 4);
				p->fragment_protocol = data[p->offset];
				hash_protocol = p->fragment_protocol;
				p->protocol = p->fragment_protocol; p->offset += 8;
				if (p->later) break;
				continue;
			}
			if (p->protocol != 0 && p->protocol != 43 && p->protocol != 60 && p->protocol != 51) break;
			if (p->offset + 2 > size || count == 15) return false;
			length = p->protocol == 51 ? (data[p->offset + 1] + 2U) * 4 : (data[p->offset + 1] + 1U) * 8;
			if (p->offset + length > size) return false;
			p->protocol = data[p->offset]; p->offset += length;
			if (!seen) hash_protocol = p->protocol;
		}
	} else return false;
	p->flow = tnlk_hash_byte(14695981039346656037ULL, version);
	for (count = 0; count < 16; ++count) p->flow = tnlk_hash_byte(p->flow, p->source.bytes[count]);
	for (count = 0; count < 16; ++count) p->flow = tnlk_hash_byte(p->flow, p->destination.bytes[count]);
	p->flow = tnlk_hash_byte(p->flow, hash_protocol);
	/* tunnel.cpp treats even an IPv6 atomic fragment as fragmented for ECMP. */
	if (!p->fragmented && !seen && (p->protocol == 6 || p->protocol == 17)) {
		if (p->offset + 4 > size) return false;
		for (count = 0; count < 4; ++count) p->flow = tnlk_hash_byte(p->flow, data[p->offset + count]);
	}
	return true;
}
static bool tk_inspect(struct tk *t, u32 network, const u8 *data, u32 size, struct tk_packet *p, bool routed)
{
	const struct tnlk_network *n = &t->state->nets[network].network;
	if (size > t->config.mtu || !tk_parse(data, size, p, false)) return false;
	if (routed ? (!tk_unicast(&p->source) || p->source.family != n->address.family) : !tk_host(n, &p->source)) return false;
	p->kind = tk_multicast(&p->destination) ? 3 : tk_broadcast(n, &p->destination) ? 2 : 1;
	return p->kind != 1 || (routed ? tk_unicast(&p->destination) : tk_host(n, &p->destination));
}

static bool tk_tuple(const u8 *data, u32 size, const struct tk_packet *p,
		     const struct tnlk_network *network, bool reply, struct tk_tuple *key, u32 *lifetime)
{
	const u8 *transport;
	if (p->later || p->offset + 4 > size || !tk_unicast(&p->source) || !tk_unicast(&p->destination)) return false;
	memset(key, 0, sizeof(*key));
	key->network = *network; key->source = reply ? p->destination : p->source;
	key->destination = reply ? p->source : p->destination; key->protocol = p->protocol;
	transport = data + p->offset;
	if (p->protocol == 6 || p->protocol == 17) {
		if (reply && p->protocol == 6 && (p->offset + 14 > size || ((transport[13] & 2) && !(transport[13] & 16)))) return false;
		key->source_port = tw_get16(transport + (reply ? 2 : 0));
		key->destination_port = tw_get16(transport + (reply ? 0 : 2));
		*lifetime = p->protocol == 6 ? 7200 : 120;
		return true;
	}
	if (p->protocol != 1 && p->protocol != 58) return false;
	if (p->offset + 8 > size || transport[0] != (p->protocol == 1 ? (reply ? 0 : 8) : (reply ? 129 : 128)) || transport[1]) return false;
	key->source_port = tw_get16(transport + 4); *lifetime = 30;
	return true;
}
static void tk_fragment_key(const struct tnlk_network *network, const struct tk_packet *p, struct tk_fragment_key *k)
{
	memset(k, 0, sizeof(*k)); k->network = *network; k->source = p->source; k->destination = p->destination;
	k->protocol = p->fragment_protocol; k->id_size = p->id_size; memcpy(k->id, p->id, sizeof(k->id));
}
static struct tk_flow *tk_flow_find(struct tk *t, const struct tk_tuple *key)
{
	u32 i;
	for (i = 0; i < TK_FLOW_LIMIT; ++i)
		if (tk_unexpired(t->flows[i].expires) && !memcmp(&t->flows[i].key, key, sizeof(*key))) return &t->flows[i];
	return NULL;
}
static bool tk_flow_key(struct tk *t, u32 network, const u8 *data, u32 size,
			struct tk_packet *p, bool reply, struct tk_tuple *key, u32 *lifetime, bool *related)
{
	const struct tnlk_network *n = &t->state->nets[network].network;
	u32 i;
	*related = false;
	if (p->later) {
		struct tk_fragment_key fragment;
		tk_fragment_key(n, p, &fragment);
		for (i = 0; i < TK_FLOW_LIMIT; ++i)
			if (tk_unexpired(t->fragments[i].expires) && t->fragments[i].reply == reply &&
			    !memcmp(&fragment, &t->fragments[i].key, sizeof(fragment))) { *key = t->fragments[i].flow; return true; }
		return false;
	}
	if (tk_tuple(data, size, p, n, reply, key, lifetime)) return true;
	if (reply && p->offset + 8 <= size &&
	    ((p->protocol == 1 && (data[p->offset] == 3 || data[p->offset] == 11 || data[p->offset] == 12)) ||
	     (p->protocol == 58 && data[p->offset] >= 1 && data[p->offset] <= 4))) {
		struct tk_packet inner;
		const u8 *quote = data + p->offset + 8;
		u32 length = size - p->offset - 8;
		if (tk_parse(quote, length, &inner, true) && tk_ip_equal(&p->destination, &inner.source) &&
		    tk_tuple(quote, length, &inner, n, false, key, lifetime)) { *related = true; return true; }
	}
	return false;
}
static void tk_fragment_remember(struct tk *t, u32 network, struct tk_packet *p,
				const struct tk_tuple *tuple, bool reply)
{
	struct tk_fragment_key key;
	u32 i, slot = TK_FLOW_LIMIT;
	if (!p->fragmented || p->later) return;
	tk_fragment_key(&t->state->nets[network].network, p, &key);
	for (i = 0; i < TK_FLOW_LIMIT; ++i) {
		if (!tk_unexpired(t->fragments[i].expires)) slot = i;
		else if (!memcmp(&key, &t->fragments[i].key, sizeof(key))) { slot = i; break; }
	}
	if (slot == TK_FLOW_LIMIT) return;
	t->fragments[slot].key = key; t->fragments[slot].flow = *tuple; t->fragments[slot].reply = reply;
	t->fragments[slot].expires = jiffies + 30 * HZ;
}
static struct tk_flow *tk_flow_lookup(struct tk *t, u32 network, const u8 *data, u32 size,
				     struct tk_packet *p, bool reply, bool *related)
{
	struct tk_tuple key;
	struct tk_flow *flow;
	u32 lifetime = 0;
	if (!tk_flow_key(t, network, data, size, p, reply, &key, &lifetime, related)) return NULL;
	flow = tk_flow_find(t, &key);
	if (flow && reply && !*related) {
		flow->expires = jiffies + flow->lifetime * HZ;
		tk_fragment_remember(t, network, p, &key, true);
	}
	return flow;
}
static bool tk_remember(struct tk *t, u32 network, const u8 *data, u32 size,
			struct tk_packet *p, const struct tnlk_endpoint *peer)
{
	struct tk_tuple key;
	struct tk_flow *flow;
	u32 lifetime = 0, i;
	bool related;
	if (!tk_flow_key(t, network, data, size, p, false, &key, &lifetime, &related)) return false;
	flow = tk_flow_find(t, &key);
	if (p->later) return flow && tk_node_equal(&flow->peer, peer);
	if (!flow) for (i = 0; i < TK_FLOW_LIMIT; ++i) {
		if (!tk_unexpired(t->flows[i].expires)) { flow = &t->flows[i]; break; }
	}
	if (!flow) return false;
	flow->key = key; flow->peer = *peer; flow->lifetime = lifetime; flow->expires = jiffies + lifetime * HZ;
	tk_fragment_remember(t, network, p, &key, false);
	return true;
}

static void tk_deliver(struct tk *t, const u8 *data, u32 size)
{
	struct sk_buff *skb;
	if (!netif_running(t->dev)) { tk_drop(t, TNLK_SEND_DROP); return; }
	skb = alloc_skb(NET_IP_ALIGN + size, GFP_ATOMIC);
	if (!skb) { tk_drop(t, TNLK_RESOURCE_DROP); return; }
	skb_reserve(skb, NET_IP_ALIGN); memcpy(skb_put(skb, size), data, size);
	skb->dev = t->dev; skb->protocol = htons(data[0] >> 4 == 4 ? ETH_P_IP : ETH_P_IPV6);
	skb_reset_network_header(skb); skb->ip_summed = CHECKSUM_NONE; skb->pkt_type = PACKET_HOST;
	t->stats.counters[TNLK_RX_PACKETS]++; t->dev->stats.rx_packets++; t->dev->stats.rx_bytes += size;
	netif_rx(skb);
}

static bool tk_udp_send(struct tk *t, const struct tnlk_endpoint *remote, const u8 *data, u32 size)
{
	struct sk_buff *skb;
	struct sock *sk = t->udp->sk;
	if (remote->ip.family == 4) {
		struct flowi4 flow = {0};
		struct rtable *route;
		flow.flowi4_proto = IPPROTO_UDP;
		flow.fl4_sport = htons(t->config.bind.port); flow.fl4_dport = htons(remote->port);
		memcpy(&flow.daddr, remote->ip.bytes, 4);
		if (t->config.bind.ip.family == 4) memcpy(&flow.saddr, t->config.bind.ip.bytes, 4);
		route = ip_route_output_key(t->net, &flow);
		if (IS_ERR(route)) return false;
		if (route->dst.dev == t->dev || size + 28 > dst_mtu(&route->dst)) { ip_rt_put(route); return false; }
		skb = alloc_skb(LL_MAX_HEADER + 28 + size, GFP_ATOMIC);
		if (!skb) { ip_rt_put(route); return false; }
		skb_reserve(skb, LL_MAX_HEADER + 28); memcpy(skb_put(skb, size), data, size);
		skb_reset_inner_network_header(skb);
		udp_tunnel_xmit_skb(route, sk, skb, flow.saddr, flow.daddr, 0, 64, htons(IP_DF),
				    flow.fl4_sport, flow.fl4_dport, false, false
#ifdef TK_UDP_XMIT_FLAGS
				    , 0
#endif
				    );
		return true;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (remote->ip.family == 6 && sk->sk_family == AF_INET6) {
		struct flowi6 flow = {0};
		struct dst_entry *dst;
		flow.flowi6_proto = IPPROTO_UDP; flow.fl6_sport = htons(t->config.bind.port); flow.fl6_dport = htons(remote->port);
		memcpy(&flow.daddr, remote->ip.bytes, 16);
		memcpy(&flow.saddr, t->config.bind.ip.bytes, 16);
		dst = ipv6_stub->ipv6_dst_lookup_flow(t->net, sk, &flow, NULL);
		if (IS_ERR(dst)) return false;
		if (dst->dev == t->dev || size + 48 > dst_mtu(dst)) { dst_release(dst); return false; }
		skb = alloc_skb(LL_MAX_HEADER + 48 + size, GFP_ATOMIC);
		if (!skb) { dst_release(dst); return false; }
		skb_reserve(skb, LL_MAX_HEADER + 48); memcpy(skb_put(skb, size), data, size);
		skb_reset_inner_network_header(skb);
		udp_tunnel6_xmit_skb(dst, sk, skb, dst->dev, &flow.saddr, &flow.daddr, 0, 64, 0,
				    flow.fl6_sport, flow.fl6_dport, false
#ifdef TK_UDP_XMIT_FLAGS
				    , 0
#endif
				    );
		return true;
	}
#endif
	return false;
}
static bool tk_send(struct tk *t, u32 peer_index, const u8 *plain, u32 size)
{
	struct tk_state *s = t->state;
	struct tnlk_peer *peer = &s->peers[peer_index];
	u8 *record;
	u32 length = size + TK_RECORD_OVERHEAD;
	int error;
	bool sent;
	if (length + (peer->endpoint.ip.family == 4 ? 28 : 48) > t->config.transport_mtu) {
		tk_drop(t, TNLK_MTU_DROP); return false;
	}
	record = kmalloc(length, GFP_ATOMIC);
	if (!record) { tk_drop(t, TNLK_RESOURCE_DROP); return false; }
	memcpy(record + TK_RECORD_HEADER, plain, size);
	error = tk_seal(s->link_crypto[peer_index], &peer->keys, 1, record, size, NULL, 0);
	if (error) {
		if (error == -EKEYEXPIRED && __ratelimit(&t->notifications)) tk_event(t, TNLK_EVENT_REKEY, &peer->endpoint, NULL, 0, NULL, 0);
		tk_drop(t, error == -ENOMEM ? TNLK_RESOURCE_DROP : TNLK_AUTH_DROP);
		kfree_sensitive(record); return false;
	}
	sent = peer->tcp ? tk_event(t, TNLK_EVENT_TCP, &peer->endpoint, NULL, 0, record, length) :
		tk_udp_send(t, &peer->endpoint, record, length);
	if (sent) t->stats.counters[peer->tcp ? TNLK_TCP_SENT : TNLK_UDP_SENT]++;
	else tk_drop(t, TNLK_SEND_DROP);
	kfree_sensitive(record); return sent;
}
static void tk_header(u8 *header, u8 kind, const struct tnlk_network *network,
		      const struct tnlk_ip *source, const struct tnlk_endpoint *destination, u64 flow, u32 length)
{
	memset(header, 0, TK_FORWARD_HEADER); header[0] = 2; header[1] = kind; header[2] = TK_HOP_LIMIT;
	memcpy(header + 4, network, sizeof(*network));
	memcpy(header + 22, source, sizeof(*source));
	if (destination) { memcpy(header + 41, &destination->ip, sizeof(destination->ip)); }
	else header[41] = 4; /* IpAddress's default unspecified family in protocol.cpp */
	tw_put64(header + 60, flow); tw_put16(header + 68, length);
}
static void tk_flood(struct tk *t, u32 network, const u8 *plain, u32 size, int excluded)
{
	u32 i;
	for (i = 0; i < t->state->header->peers; ++i)
		if (i != excluded && t->state->peers[i].ready &&
		    (t->state->peers[i].networks[network / 8] & (1 << (network % 8)))) tk_send(t, i, plain, size);
}
static void tk_unicast_send(struct tk *t, u32 network, const struct tnlk_endpoint *destination,
			    const u8 *packet, u32 size, u64 flow)
{
	struct tk_state *s = t->state;
	u8 *plain, aad[TK_FORWARD_AAD];
	u32 i, length = TK_FORWARD_HEADER + TK_RECORD_OVERHEAD + size;
	int next = tk_next(s, tk_route(s, network, destination), flow), error;
	if (next < 0) { tk_drop(t, TNLK_NO_ROUTE); return; }
	for (i = 0; i < s->header->ends; ++i)
		if (s->ends[i].network == network && s->ends[i].ready && tk_node_equal(&s->ends[i].destination, destination)) break;
	if (i == s->header->ends) {
		tk_drop(t, TNLK_NO_SESSION);
		if (__ratelimit(&t->notifications)) tk_event(t, TNLK_EVENT_NEED_SESSION, destination, &s->nets[network].network, 0, NULL, 0);
		return;
	}
	plain = kmalloc(length, GFP_ATOMIC);
	if (!plain) { tk_drop(t, TNLK_RESOURCE_DROP); return; }
	tk_header(plain, 1, &s->nets[network].network, &s->nets[network].local_ip, destination, flow, size + TK_RECORD_OVERHEAD);
	memcpy(aad, plain, sizeof(aad)); aad[2] = 0;
	memcpy(plain + TK_FORWARD_HEADER + TK_RECORD_HEADER, packet, size);
	error = tk_seal(s->end_crypto[i], &s->ends[i].keys, 2, plain + TK_FORWARD_HEADER, size, aad, sizeof(aad));
	if (!error) tk_send(t, next, plain, length);
	else {
		if (error == -EKEYEXPIRED && __ratelimit(&t->notifications)) tk_event(t, TNLK_EVENT_REKEY, destination, &s->nets[network].network, 0, NULL, 0);
		tk_drop(t, error == -ENOMEM ? TNLK_RESOURCE_DROP : TNLK_AUTH_DROP);
	}
	kfree_sensitive(plain);
}

static void tk_from_device(struct tk *t, const u8 *data, u32 size)
{
	struct tk_state *s = t->state;
	u32 n;
	if (!tk_live(t)) { tk_drop(t, TNLK_POLICY_DROP); return; }
	for (n = 0; n < s->header->networks; ++n) {
		struct tk_packet p;
		struct tnlk_endpoint local_node = { .ip = s->nets[n].local_ip, .port = 0 };
		struct tnlk_endpoint *destination;
		struct tnlk_route *route;
		struct tk_flow *binding;
		bool related;
		if (!tk_inspect(t, n, data, size, &p, true)) continue;
		if (!tk_ip_equal(&p.source, &s->nets[n].local_ip)) {
			if (p.kind != 1) continue;
			binding = tk_flow_lookup(t, n, data, size, &p, true, &related);
			if (!binding || !tk_published(s, n, &local_node, &binding->key.destination, true) ||
			    (!related && !tk_published(s, n, &local_node, &p.source, true))) continue;
			route = tk_route(s, n, &binding->peer);
			if (!route || !tk_ip_equal(&route->ip, &p.destination)) continue;
			tk_unicast_send(t, n, &binding->peer, data, size, p.flow); return;
		}
		if (p.kind != 1) {
			u8 *plain;
			if (!tk_inspect(t, n, data, size, &p, false)) break;
			plain = kmalloc(TK_FORWARD_HEADER + size, GFP_ATOMIC);
			if (!plain) { tk_drop(t, TNLK_RESOURCE_DROP); return; }
			tk_header(plain, p.kind, &s->nets[n].network, &s->nets[n].local_ip, NULL, p.flow, size);
			memcpy(plain + TK_FORWARD_HEADER, data, size);
			tk_flood(t, n, plain, TK_FORWARD_HEADER + size, -1); kfree_sensitive(plain); return;
		}
		if (tk_ip_equal(&p.destination, &s->nets[n].local_ip)) { tk_deliver(t, data, size); return; }
		if (tk_host(&s->nets[n].network, &p.destination)) {
			route = tk_route_ip(s, n, &p.destination);
			if (!route) { tk_drop(t, TNLK_NO_ROUTE); return; }
			destination = &route->destination;
		} else {
			destination = tk_gateway(s, n, &p.destination);
			if (!destination) { tk_drop(t, TNLK_NO_ROUTE); return; }
			binding = tk_flow_lookup(t, n, data, size, &p, false, &related);
			if (binding && tk_route(s, n, &binding->peer) && tk_published(s, n, &binding->peer, &p.destination, false)) destination = &binding->peer;
			if (!tk_remember(t, n, data, size, &p, destination)) { tk_drop(t, TNLK_POLICY_DROP); return; }
		}
		tk_unicast_send(t, n, destination, data, size, p.flow); return;
	}
	tk_drop(t, size > t->config.mtu ? TNLK_MTU_DROP : TNLK_POLICY_DROP);
}

static void tk_forward(struct tk *t, u32 incoming, u8 *plain, u32 size)
{
	struct tk_state *s = t->state;
	struct tnlk_network network;
	struct tnlk_endpoint source, destination;
	struct tnlk_endpoint local_node;
	struct tnlk_route *source_route;
	struct tk_packet p;
	u8 *payload, aad[TK_FORWARD_AAD];
	u32 n, payload_size, i;
	u64 flow;
	int decoded, next;
	if (size < TK_FORWARD_HEADER || plain[0] != 2 || plain[1] < 1 || plain[1] > 3 || !plain[2] || plain[3]) goto invalid;
	memcpy(&network, plain + 4, sizeof(network));
	memcpy(&source.ip, plain + 22, sizeof(source.ip)); source.port = tw_get16(plain + 39);
	memcpy(&destination.ip, plain + 41, sizeof(destination.ip)); destination.port = tw_get16(plain + 58);
	if (!tk_node_valid(&source) || !tk_ip_valid(&destination.ip)) goto invalid;
	if (plain[1] == 1) { if (!tk_node_valid(&destination)) goto invalid; }
	else { static const u8 zero[16]; if (destination.port || memcmp(destination.ip.bytes, zero, 16)) goto invalid; }
	payload_size = tw_get16(plain + 68);
	if (payload_size + TK_FORWARD_HEADER != size) goto invalid;
	for (n = 0; n < s->header->networks; ++n) if (tk_network_equal(&s->nets[n].network, &network)) break;
	if (n == s->header->networks || !(s->peers[incoming].networks[n / 8] & (1 << (n % 8)))) goto invalid;
	local_node.ip = s->nets[n].local_ip; local_node.port = 0;
	if (tk_ip_equal(&source.ip, &s->nets[n].local_ip)) goto invalid;
	payload = plain + TK_FORWARD_HEADER; flow = tw_get64(plain + 60);
	if (plain[1] == 1 && !tk_ip_equal(&destination.ip, &s->nets[n].local_ip)) {
		if (plain[2] <= 1) goto invalid;
		next = tk_next(s, tk_route(s, n, &destination), flow);
		if (next < 0 || next == incoming) { tk_drop(t, TNLK_NO_ROUTE); return; }
		plain[2]--;
		if (tk_send(t, next, plain, size)) t->stats.counters[TNLK_FORWARDED]++;
		return;
	}
	source_route = tk_route(s, n, &source);
	if (!source_route) goto invalid;
	if (plain[1] != 1) {
		if (!source_route->nhops || source_route->hops[0] != incoming) { tk_drop(t, TNLK_RPF_DROP); return; }
		if (!tk_inspect(t, n, payload, payload_size, &p, false) || p.kind != plain[1] || p.flow != flow ||
		    !tk_ip_equal(&p.source, &source_route->ip) || tk_ip_equal(&p.source, &s->nets[n].local_ip)) goto invalid;
		tk_deliver(t, payload, payload_size);
		if (plain[2] > 1) { plain[2]--; tk_flood(t, n, plain, size, incoming); t->stats.counters[TNLK_FORWARDED]++; }
		return;
	}
	for (i = 0; i < s->header->ends; ++i)
		if (s->ends[i].network == n && tk_node_equal(&s->ends[i].destination, &source)) break;
	if (i == s->header->ends) { tk_drop(t, TNLK_NO_SESSION); return; }
	memcpy(aad, plain, sizeof(aad)); aad[2] = 0;
	decoded = tk_open_record(s->end_crypto[i], &s->ends[i].keys, 2, payload, payload_size, aad, sizeof(aad));
	if (decoded < 0) { tk_drop(t, decoded == -EALREADY ? TNLK_REPLAY_DROP : TNLK_AUTH_DROP); return; }
	payload += TK_RECORD_HEADER; payload_size = decoded;
	if (!tk_inspect(t, n, payload, payload_size, &p, true) || p.kind != 1 || p.flow != flow) goto invalid;
	if (tk_ip_equal(&p.source, &source_route->ip)) {
		if (!tk_ip_equal(&p.destination, &s->nets[n].local_ip) &&
		    (!tk_published(s, n, &local_node, &p.destination, true) || !tk_remember(t, n, payload, payload_size, &p, &source))) goto invalid;
	} else {
		struct tk_flow *binding;
		bool related;
		if (!tk_ip_equal(&p.destination, &s->nets[n].local_ip)) goto invalid;
		binding = tk_flow_lookup(t, n, payload, payload_size, &p, true, &related);
		if (!binding || !tk_node_equal(&binding->peer, &source) ||
		    !tk_published(s, n, &source, &binding->key.destination, false) ||
		    (!related && !tk_published(s, n, &source, &p.source, false))) goto invalid;
	}
	tk_deliver(t, payload, payload_size); return;
invalid:
	tk_drop(t, TNLK_POLICY_DROP);
}

static void tk_receive(struct tk *t, const struct tnlk_endpoint *from, u8 *record, u32 size, bool tcp)
{
	u32 i;
	int length;
	u8 *plain;
	if (!tk_live(t)) { tk_drop(t, TNLK_POLICY_DROP); return; }
	if (size < TK_RECORD_OVERHEAD || size + (from->ip.family == 4 ? 28 : 48) > t->config.transport_mtu) {
		tk_drop(t, TNLK_MTU_DROP); return;
	}
	for (i = 0; i < t->state->header->peers; ++i)
		if (tk_endpoint_equal(from, &t->state->peers[i].endpoint) && tcp == !!t->state->peers[i].tcp &&
		    !memcmp(record + 8, t->state->peers[i].keys.id, 16)) break;
	if (i == t->state->header->peers) { tk_drop(t, TNLK_AUTH_DROP); return; }
	length = tk_open_record(t->state->link_crypto[i], &t->state->peers[i].keys, 1, record, size, NULL, 0);
	if (length < 0) { tk_drop(t, length == -EALREADY ? TNLK_REPLAY_DROP : TNLK_AUTH_DROP); return; }
	t->stats.counters[tcp ? TNLK_TCP_RECEIVED : TNLK_UDP_RECEIVED]++;
	plain = record + TK_RECORD_HEADER;
	if (length == 9 && (plain[0] == 4 || plain[0] == 5)) {
		if (plain[0] == 4) { plain[0] = 5; tk_send(t, i, plain, length); }
		else if (!tk_event(t, TNLK_EVENT_PROBE_ACK, from, NULL, tw_get64(plain + 1), NULL, 0)) tk_drop(t, TNLK_RESOURCE_DROP);
	} else if (t->state->peers[i].ready) tk_forward(t, i, plain, length);
	else tk_drop(t, TNLK_POLICY_DROP);
}

static int tk_udp_receive(struct sock *sk, struct sk_buff *skb)
{
	struct tk *t = rcu_dereference_sk_user_data(sk);
	struct tnlk_endpoint from = {0};
	u8 *record;
	u32 length;
	if (!t || skb->len < sizeof(struct udphdr) + TK_RECORD_OVERHEAD) goto done;
	if (!pskb_may_pull(skb, sizeof(struct udphdr))) goto done;
	from.port = ntohs(udp_hdr(skb)->source);
	if (skb->protocol == htons(ETH_P_IP)) { from.ip.family = 4; memcpy(from.ip.bytes, &ip_hdr(skb)->saddr, 4); }
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) { from.ip.family = 6; memcpy(from.ip.bytes, &ipv6_hdr(skb)->saddr, 16); }
#endif
	else goto done;
	length = skb->len - sizeof(struct udphdr);
	if (length > TNLK_MAX_PACKET || length + (from.ip.family == 4 ? 28 : 48) > t->config.transport_mtu) goto done;
	record = kmalloc(length, GFP_ATOMIC);
	if (!record) goto done;
	if (!skb_copy_bits(skb, sizeof(struct udphdr), record, length)) {
		spin_lock_bh(&t->lock); tk_receive(t, &from, record, length, false); spin_unlock_bh(&t->lock);
	}
	kfree_sensitive(record);
done:
	kfree_skb(skb); return 0;
}
static netdev_tx_t tk_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tk *t = *(struct tk **)netdev_priv(dev);
	u8 *data = NULL;
	if (!skb_is_gso(skb) && skb->len <= t->config.mtu &&
	    (skb->ip_summed != CHECKSUM_PARTIAL || !skb_checksum_help(skb))) {
		data = kmalloc(skb->len, GFP_ATOMIC);
		if (data && skb_copy_bits(skb, 0, data, skb->len)) { kfree_sensitive(data); data = NULL; }
	}
	spin_lock_bh(&t->lock);
	if (data) {
		t->stats.counters[TNLK_TX_PACKETS]++; dev->stats.tx_packets++; dev->stats.tx_bytes += skb->len;
		tk_from_device(t, data, skb->len);
	} else tk_drop(t, skb->len > t->config.mtu ? TNLK_MTU_DROP : TNLK_RESOURCE_DROP);
	spin_unlock_bh(&t->lock);
	kfree_sensitive(data); dev_kfree_skb(skb); return NETDEV_TX_OK;
}
static int tk_net_open(struct net_device *dev) { netif_start_queue(dev); return 0; }
static int tk_net_stop(struct net_device *dev) { netif_stop_queue(dev); return 0; }
static const struct net_device_ops tk_net_ops = {
	.ndo_open = tk_net_open, .ndo_stop = tk_net_stop, .ndo_start_xmit = tk_xmit,
};
static void tk_net_setup(struct net_device *dev)
{
	dev->netdev_ops = &tk_net_ops; dev->type = ARPHRD_NONE; dev->hard_header_len = 0;
	dev->addr_len = 0; dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
#ifdef TK_NETNS_IMMUTABLE
	dev->netns_immutable = true;
#else
	dev->features = NETIF_F_NETNS_LOCAL;
#endif
	dev->tx_queue_len = 0; dev->mtu = 1280; dev->min_mtu = 68; dev->max_mtu = 65535 - 214;
}

static void tk_state_free(struct tk_state *s)
{
	u32 i;
	if (!s) return;
	if (s->link_crypto) for (i = 0; i < s->header->peers; ++i) tk_crypto_free(s->link_crypto[i]);
	if (s->end_crypto) for (i = 0; i < s->header->ends; ++i) tk_crypto_free(s->end_crypto[i]);
	kvfree(s->link_crypto); kvfree(s->end_crypto);
	if (s->blob) {
		size_t bytes = sizeof(*s->header) + s->header->networks * sizeof(*s->nets) +
			s->header->peers * sizeof(*s->peers) + s->header->routes * sizeof(*s->routes) +
			s->header->ends * sizeof(*s->ends) + s->header->prefixes * sizeof(*s->prefixes);
		kvfree_sensitive(s->blob, bytes);
	}
	kfree(s);
}
static bool tk_keys_valid(const struct tnlk_keys *keys)
{ return memcmp(keys->send, keys->receive, 32); }
static bool tk_has_end(struct tk_state *s, u32 network, const struct tnlk_endpoint *destination)
{
	u32 i;
	for (i = 0; i < s->header->ends; ++i)
		if (s->ends[i].network == network && tk_node_equal(&s->ends[i].destination, destination)) return true;
	return false;
}
/* Retain established return permission across unrelated route/ECMP updates,
 * but never resurrect it after its network, endpoint, key or export vanished. */
static void tk_prune_flows(struct tk *t, struct tk_state *old, struct tk_state *next)
{
	u32 i, a, b;
	for (i = 0; i < TK_FLOW_LIMIT; ++i) {
		struct tk_flow *flow = &t->flows[i];
		struct tnlk_route *before, *after;
		bool valid = false;
		if (!tk_unexpired(flow->expires)) continue;
		if (!old) goto discard;
		for (a = 0; a < old->header->networks; ++a)
			if (tk_network_equal(&flow->key.network, &old->nets[a].network)) break;
		for (b = 0; b < next->header->networks; ++b)
			if (tk_network_equal(&flow->key.network, &next->nets[b].network)) break;
		if (a == old->header->networks || b == next->header->networks ||
		    !tk_ip_equal(&old->nets[a].local_ip, &next->nets[b].local_ip)) goto discard;
		before = tk_route(old, a, &flow->peer); after = tk_route(next, b, &flow->peer);
		if (!before || !after || !tk_ip_equal(&before->ip, &after->ip) ||
		    (tk_has_end(old, a, &flow->peer) && !tk_has_end(next, b, &flow->peer))) goto discard;
		{
			struct tnlk_endpoint local_node = { .ip = next->nets[b].local_ip, .port = 0 };
		if (tk_ip_equal(&flow->key.source, &next->nets[b].local_ip))
			valid = tk_published(next, b, &flow->peer, &flow->key.destination, false);
		else valid = tk_ip_equal(&flow->key.source, &after->ip) &&
			tk_published(next, b, &local_node, &flow->key.destination, true);
		}
discard:
		if (!valid) flow->expires = 0;
	}
	for (i = 0; i < TK_FLOW_LIMIT; ++i)
		if (tk_unexpired(t->fragments[i].expires) && !tk_flow_find(t, &t->fragments[i].flow)) t->fragments[i].expires = 0;
}
static int tk_validate_state(struct tk *t, struct tk_state *s)
{
	u32 i, j, k;
	for (i = 0; i < s->header->networks; ++i) {
		if (!tk_network_valid(&s->nets[i].network) || !tk_host(&s->nets[i].network, &s->nets[i].local_ip)) return -EINVAL;
		for (j = 0; j < i; ++j)
			if (tk_contains(&s->nets[i].network, &s->nets[j].network.address) || tk_contains(&s->nets[j].network, &s->nets[i].network.address)) return -EINVAL;
	}
	for (i = 0; i < s->header->peers; ++i) {
		struct tnlk_peer *p = &s->peers[i];
		if (!tk_endpoint_valid(&p->endpoint) || tk_endpoint_equal(&p->endpoint, &t->config.local) ||
		    !tk_keys_valid(&p->keys) || p->tcp > 1 || p->ready > 1 ||
		    (!p->tcp && p->endpoint.ip.family == 6 && t->config.bind.ip.family != 6)) return -EINVAL;
		for (j = s->header->networks; j < TNLK_MAX_NETWORKS; ++j)
			if (p->networks[j / 8] & (1 << (j % 8))) return -EINVAL;
		for (j = 0; j < i; ++j)
			if (tk_endpoint_equal(&p->endpoint, &s->peers[j].endpoint) || !memcmp(p->keys.id, s->peers[j].keys.id, 16)) return -EINVAL;
	}
	for (i = 0; i < s->header->routes; ++i) {
		struct tnlk_route *r = &s->routes[i];
		if (r->network >= s->header->networks || !tk_node_valid(&r->destination) ||
		    tk_ip_equal(&r->destination.ip, &s->nets[r->network].local_ip) || !tk_host(&s->nets[r->network].network, &r->ip) ||
		    tk_ip_equal(&r->ip, &s->nets[r->network].local_ip) || !r->nhops || r->nhops > TNLK_MAX_HOPS) return -EINVAL;
		for (j = 0; j < r->nhops; ++j) {
			if (r->hops[j] >= s->header->peers || !s->peers[r->hops[j]].ready ||
			    !(s->peers[r->hops[j]].networks[r->network / 8] & (1 << (r->network % 8)))) return -EINVAL;
			for (k = 0; k < j; ++k) if (r->hops[k] == r->hops[j]) return -EINVAL;
		}
		for (j = 0; j < i; ++j)
			if (s->routes[j].network == r->network && (tk_node_equal(&s->routes[j].destination, &r->destination) || tk_ip_equal(&s->routes[j].ip, &r->ip))) return -EINVAL;
	}
	for (i = 0; i < s->header->ends; ++i) {
		struct tnlk_end *e = &s->ends[i];
		if (e->network >= s->header->networks || !tk_node_valid(&e->destination) ||
		    tk_ip_equal(&e->destination.ip, &s->nets[e->network].local_ip) || !tk_keys_valid(&e->keys) || e->ready > 1) return -EINVAL;
		for (j = 0; j < i; ++j)
			if (!memcmp(e->keys.id, s->ends[j].keys.id, 16) ||
			    (e->network == s->ends[j].network && tk_node_equal(&e->destination, &s->ends[j].destination))) return -EINVAL;
	}
	for (i = 0; i < s->header->prefixes; ++i) {
		struct tnlk_prefix *p = &s->prefixes[i];
		if (p->network >= s->header->networks || !tk_network_valid(&p->prefix) || !tk_node_valid(&p->publisher) || p->selected > 1 ||
		    p->prefix.address.family != s->nets[p->network].network.address.family) return -EINVAL;
		if (tk_contains(&p->prefix, &s->nets[p->network].network.address) || tk_contains(&s->nets[p->network].network, &p->prefix.address)) return -EINVAL;
	}
	return 0;
}
static int tk_snapshot(struct tk *t, const struct tnlk_blob *blob)
{
	struct tk_state *s, *old;
	struct tnlk_snapshot *h;
	u8 *cursor;
	size_t size;
	u32 i, j;
	int error = -EINVAL;
	if (!t->dev || blob->reserved || blob->length < sizeof(*h) || blob->length > TNLK_MAX_BLOB) return -EINVAL;
	if (t->state && time_after_eq(jiffies, t->deadline)) return -ESTALE;
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) return -ENOMEM;
	s->blob = kvmalloc(blob->length, GFP_KERNEL);
	if (!s->blob) { kfree(s); return -ENOMEM; }
	if (copy_from_user(s->blob, u64_to_user_ptr(blob->data), blob->length)) { error = -EFAULT; goto fail_early; }
	h = s->header = s->blob;
	if (h->abi != TNLK_ABI || h->networks > TNLK_MAX_NETWORKS || h->peers > TNLK_MAX_PEERS ||
	    h->routes > TNLK_MAX_ROUTES || h->ends > TNLK_MAX_ENDS || h->prefixes > TNLK_MAX_PREFIXES) goto fail_early;
	size = sizeof(*h) + h->networks * sizeof(*s->nets) + h->peers * sizeof(*s->peers) +
		h->routes * sizeof(*s->routes) + h->ends * sizeof(*s->ends) + h->prefixes * sizeof(*s->prefixes);
	if (size != blob->length) goto fail_early;
	cursor = (u8 *)(h + 1); s->nets = (void *)cursor; cursor += h->networks * sizeof(*s->nets);
	s->peers = (void *)cursor; cursor += h->peers * sizeof(*s->peers);
	s->routes = (void *)cursor; cursor += h->routes * sizeof(*s->routes);
	s->ends = (void *)cursor; cursor += h->ends * sizeof(*s->ends); s->prefixes = (void *)cursor;
	error = tk_validate_state(t, s);
	if (error) goto fail;
	s->link_crypto = kvcalloc(h->peers, sizeof(*s->link_crypto), GFP_KERNEL);
	s->end_crypto = kvcalloc(h->ends, sizeof(*s->end_crypto), GFP_KERNEL);
	if ((!s->link_crypto && h->peers) || (!s->end_crypto && h->ends)) { error = -ENOMEM; goto fail; }
	for (i = 0; i < h->peers; ++i) {
		struct tk_crypto *c = tk_crypto_new(&s->peers[i].keys);
		if (IS_ERR(c)) { error = PTR_ERR(c); goto fail; } s->link_crypto[i] = c;
	}
	for (i = 0; i < h->ends; ++i) {
		struct tk_crypto *c = tk_crypto_new(&s->ends[i].keys);
		if (IS_ERR(c)) { error = PTR_ERR(c); goto fail; } s->end_crypto[i] = c;
	}
	spin_lock_bh(&t->lock);
	old = t->state;
	/* Crypto allocations above may sleep; expiration during their construction
	 * must not let a late snapshot resurrect the old authorization. */
	if (old && time_after_eq(jiffies, t->deadline)) { error = -ESTALE; goto unlock; }
	if (old) {
		for (i = 0; i < h->peers; ++i) for (j = 0; j < old->header->peers; ++j) {
			if (memcmp(s->peers[i].keys.id, old->peers[j].keys.id, 16)) continue;
			if (memcmp(&s->peers[i].keys, &old->peers[j].keys, sizeof(struct tnlk_keys)) ||
			    !tk_endpoint_equal(&s->peers[i].endpoint, &old->peers[j].endpoint) || s->peers[i].tcp != old->peers[j].tcp) {
				error = -EKEYREJECTED; goto unlock;
			}
			s->link_crypto[i]->next = old->link_crypto[j]->next;
			s->link_crypto[i]->highest = old->link_crypto[j]->highest;
			s->link_crypto[i]->window = old->link_crypto[j]->window;
		}
		for (i = 0; i < h->ends; ++i) for (j = 0; j < old->header->ends; ++j) {
			if (memcmp(s->ends[i].keys.id, old->ends[j].keys.id, 16)) continue;
			if (memcmp(&s->ends[i].keys, &old->ends[j].keys, sizeof(struct tnlk_keys)) ||
			    !tk_node_equal(&s->ends[i].destination, &old->ends[j].destination) ||
			    !tk_network_equal(&s->nets[s->ends[i].network].network, &old->nets[old->ends[j].network].network)) {
				error = -EKEYREJECTED; goto unlock;
			}
			s->end_crypto[i]->next = old->end_crypto[j]->next;
			s->end_crypto[i]->highest = old->end_crypto[j]->highest;
			s->end_crypto[i]->window = old->end_crypto[j]->window;
		}
	}
	tk_prune_flows(t, old, s);
	t->state = s;
	t->deadline = jiffies + msecs_to_jiffies(t->config.lease_ms);
	spin_unlock_bh(&t->lock);
	tk_state_free(old); return 0;
unlock:
	spin_unlock_bh(&t->lock);
fail:
	tk_state_free(s); return error;
fail_early:
	kvfree_sensitive(s->blob, blob->length); kfree(s); return error;
}

static int tk_create(struct tk *t, struct tnlk_create *config)
{
	struct udp_port_cfg port = {0};
	struct udp_tunnel_sock_cfg sock_config = {0};
	struct net_device *dev;
	int error;
	if (t->dev) return -EALREADY;
	if (config->abi != TNLK_ABI || !tk_endpoint_valid(&config->local) || !tk_ip_valid(&config->bind.ip) ||
	    !config->bind.port || config->mtu < 68 || config->mtu > 65535 - 214 || config->transport_mtu > 65535 ||
	    config->mtu + (config->bind.ip.family == 4 ? 194 : 214) > config->transport_mtu ||
	    config->lease_ms < 1000 || config->lease_ms > 60000 ||
	    !memchr(config->name, 0, sizeof(config->name))) return -EINVAL;
	dev = alloc_netdev(sizeof(struct tk *), config->name[0] ? config->name : "tnk%d", NET_NAME_USER, tk_net_setup);
	if (!dev) return -ENOMEM;
	dev_net_set(dev, t->net); *(struct tk **)netdev_priv(dev) = t; dev->mtu = config->mtu;
	port.family = config->bind.ip.family == 4 ? AF_INET : AF_INET6;
	port.local_udp_port = htons(config->bind.port); port.use_udp_checksums = 1;
#if IS_ENABLED(CONFIG_IPV6)
	port.use_udp6_tx_checksums = 1; port.use_udp6_rx_checksums = 1; port.ipv6_v6only = 0;
	if (port.family == AF_INET6) memcpy(&port.local_ip6, config->bind.ip.bytes, 16);
	else
#endif
	memcpy(&port.local_ip, config->bind.ip.bytes, 4);
	error = udp_sock_create(t->net, &port, &t->udp);
	if (error) { free_netdev(dev); return error; }
	t->config = *config; t->dev = dev;
	sock_config.sk_user_data = t; sock_config.encap_type = 1; sock_config.encap_rcv = tk_udp_receive;
	setup_udp_tunnel_sock(t->net,
#ifdef TK_SETUP_USES_SK
			      t->udp->sk,
#else
			      t->udp,
#endif
			      &sock_config);
	error = register_netdev(dev);
	if (error) { udp_tunnel_sock_release(t->udp); t->udp = NULL; t->dev = NULL; free_netdev(dev); return error; }
	strscpy(config->name, dev->name, sizeof(config->name)); config->ifindex = dev->ifindex;
	t->config = *config; t->deadline = jiffies + msecs_to_jiffies(config->lease_ms);
	return 0;
}
static long tk_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	struct tk *t = file->private_data;
	void __user *user = (void __user *)argument;
	long error = 0;
	if (!ns_capable(t->net->user_ns, CAP_NET_ADMIN)) return -EPERM;
	mutex_lock(&t->control);
	switch (command) {
	case TNLK_CREATE: {
		struct tnlk_create config;
		if (copy_from_user(&config, user, sizeof(config))) { error = -EFAULT; break; }
		error = tk_create(t, &config);
		if (!error && copy_to_user(user, &config, sizeof(config))) error = -EFAULT;
		break;
	}
	case TNLK_SNAPSHOT: {
		struct tnlk_blob blob;
		if (copy_from_user(&blob, user, sizeof(blob))) { error = -EFAULT; break; }
		error = tk_snapshot(t, &blob); break;
	}
	case TNLK_PROBE: {
		struct tnlk_probe probe;
		u8 plain[9] = {4};
		u32 i;
		if (copy_from_user(&probe, user, sizeof(probe))) { error = -EFAULT; break; }
		spin_lock_bh(&t->lock);
		if (!tk_live(t)) error = -ENETDOWN;
		else {
			for (i = 0; i < t->state->header->peers; ++i) if (tk_endpoint_equal(&probe.peer, &t->state->peers[i].endpoint)) break;
			if (i == t->state->header->peers) error = -ENOENT;
			else { tw_put64(plain + 1, probe.token); if (!tk_send(t, i, plain, sizeof(plain))) error = -EAGAIN; }
		}
		spin_unlock_bh(&t->lock); break;
	}
	case TNLK_STATS: {
		struct tnlk_stats stats;
		spin_lock_bh(&t->lock); stats = t->stats; spin_unlock_bh(&t->lock);
		if (copy_to_user(user, &stats, sizeof(stats))) error = -EFAULT;
		break;
	}
	case TNLK_RENEW:
		spin_lock_bh(&t->lock);
		if (!t->dev) error = -ENODEV;
		else if (t->state && time_after_eq(jiffies, t->deadline)) error = -ESTALE;
		else t->deadline = jiffies + msecs_to_jiffies(t->config.lease_ms);
		spin_unlock_bh(&t->lock); break;
	default: error = -ENOTTY;
	}
	mutex_unlock(&t->control); return error;
}
static ssize_t tk_read(struct file *file, char __user *buffer, size_t length, loff_t *position)
{
	struct tk *t = file->private_data;
	struct sk_buff *skb;
	ssize_t result;
	if (mutex_lock_interruptible(&t->reader)) return -ERESTARTSYS;
	for (;;) {
		skb = skb_peek(&t->events);
		if (skb) break;
		if (file->f_flags & O_NONBLOCK) { result = -EAGAIN; goto done; }
		result = wait_event_interruptible(t->wait, !skb_queue_empty(&t->events) || READ_ONCE(t->closing));
		if (result) goto done;
		if (READ_ONCE(t->closing)) { result = 0; goto done; }
	}
	if (length < skb->len) { result = -EMSGSIZE; goto done; }
	if (copy_to_user(buffer, skb->data, skb->len)) { result = -EFAULT; goto done; }
	skb = skb_dequeue(&t->events); result = skb->len;
	atomic_sub(skb->len, &t->event_bytes); kfree_skb(skb);
done:
	mutex_unlock(&t->reader); return result;
}
static ssize_t tk_write(struct file *file, const char __user *buffer, size_t length, loff_t *position)
{
	struct tk *t = file->private_data;
	struct tnlk_event *event;
	u8 *bytes;
	if (length < sizeof(*event) + TK_RECORD_OVERHEAD || length > sizeof(*event) + TNLK_MAX_PACKET) return -EMSGSIZE;
	bytes = memdup_user(buffer, length);
	if (IS_ERR(bytes)) return PTR_ERR(bytes);
	event = (struct tnlk_event *)bytes;
	if (event->kind != TNLK_EVENT_TCP || event->length != length - sizeof(*event) || !tk_endpoint_valid(&event->peer)) {
		kfree_sensitive(bytes); return -EINVAL;
	}
	spin_lock_bh(&t->lock); tk_receive(t, &event->peer, bytes + sizeof(*event), event->length, true); spin_unlock_bh(&t->lock);
	kfree_sensitive(bytes); return length;
}
static __poll_t tk_poll(struct file *file, poll_table *wait)
{
	struct tk *t = file->private_data;
	__poll_t mask = EPOLLOUT | EPOLLWRNORM;
	poll_wait(file, &t->wait, wait);
	if (!skb_queue_empty(&t->events)) mask |= EPOLLIN | EPOLLRDNORM;
	if (READ_ONCE(t->closing)) mask |= EPOLLHUP;
	return mask;
}
static int tk_file_open(struct inode *inode, struct file *file)
{
	struct tk *t;
	struct net *net = current->nsproxy->net_ns;
	if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) return -EPERM;
	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t) return -ENOMEM;
	t->flows = kvcalloc(TK_FLOW_LIMIT, sizeof(*t->flows), GFP_KERNEL);
	t->fragments = kvcalloc(TK_FLOW_LIMIT, sizeof(*t->fragments), GFP_KERNEL);
	if (!t->flows || !t->fragments) { kvfree(t->flows); kvfree(t->fragments); kfree(t); return -ENOMEM; }
	mutex_init(&t->control); mutex_init(&t->reader); spin_lock_init(&t->lock);
	skb_queue_head_init(&t->events); init_waitqueue_head(&t->wait); atomic_set(&t->event_bytes, 0);
	ratelimit_state_init(&t->notifications, HZ, 32);
	t->net = get_net(net); file->private_data = t;
	return nonseekable_open(inode, file);
}
static int tk_release(struct inode *inode, struct file *file)
{
	struct tk *t = file->private_data;
	spin_lock_bh(&t->lock); t->closing = true; spin_unlock_bh(&t->lock);
	wake_up_interruptible(&t->wait);
	if (t->udp) udp_tunnel_sock_release(t->udp);
	if (t->dev) { unregister_netdev(t->dev); free_netdev(t->dev); }
	tk_state_free(t->state); skb_queue_purge(&t->events);
	kvfree(t->flows); kvfree(t->fragments); put_net(t->net); kfree(t); return 0;
}
static const struct file_operations tk_file_ops = {
	.owner = THIS_MODULE, .open = tk_file_open, .release = tk_release,
	.unlocked_ioctl = tk_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
	.read = tk_read, .write = tk_write, .poll = tk_poll,
};
static struct miscdevice tk_misc = {
	.minor = MISC_DYNAMIC_MINOR, .name = "tunnel_kmod", .fops = &tk_file_ops, .mode = 0600,
};
static int __init tk_init(void) { return misc_register(&tk_misc); }
static void __exit tk_exit(void) { misc_deregister(&tk_misc); }
module_init(tk_init);
module_exit(tk_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Optional in-kernel UDP data plane for tunnel protocol v1");
MODULE_AUTHOR("Tunnel contributors");
