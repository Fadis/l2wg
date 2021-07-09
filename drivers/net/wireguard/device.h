/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_DEVICE_H
#define _WG_DEVICE_H

#include "noise.h"
#include "allowedips.h"
#include "peerlookup.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/ptr_ring.h>

struct wg_device;
struct wg_peer;

struct multicore_worker {
	void *ptr;
	struct work_struct work;
};

struct crypt_queue {
	struct ptr_ring ring;
	union {
		struct {
			struct multicore_worker __percpu *worker;
			int last_cpu;
		};
		struct work_struct work;
	};
};

struct wg_device {
	struct net_device *dev;
	struct crypt_queue encrypt_queue, decrypt_queue;
	struct sock __rcu *sock4, *sock6;
	struct net __rcu *creating_net;
	struct noise_static_identity static_identity;
	struct workqueue_struct *handshake_receive_wq, *handshake_send_wq;
	struct workqueue_struct *packet_crypt_wq;
	struct sk_buff_head incoming_handshakes;
	int incoming_handshake_cpu;
	struct multicore_worker __percpu *incoming_handshakes_worker;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable *peer_hashtable;
	struct index_hashtable *index_hashtable;
	struct allowedips peer_allowedips;
	struct mutex device_update_lock, socket_update_lock;
	struct list_head device_list, peer_list;
	unsigned int num_peers, device_update_gen;
	u32 fwmark;
	u16 incoming_port;
	bool l2;
	struct wg_peer *(*allowedips_lookup_src)(struct allowedips *table,
					 struct sk_buff *skb);
	struct wg_peer *(*allowedips_lookup_dst)(struct allowedips *table,
					 struct sk_buff *skb);
	bool (*check_packet_length)( struct sk_buff *skb,  struct net_device *dev );
	unsigned int (*get_packet_length)( struct sk_buff *skb );
};

int wg_device_init(void);
void wg_device_uninit(void);
bool wg_check_packet_length( struct sk_buff *skb,  struct net_device *dev );
bool l2wg_check_packet_length( struct sk_buff *skb,  struct net_device *dev );
unsigned int wg_get_packet_length( struct sk_buff *skb );
unsigned int l2wg_get_packet_length( struct sk_buff *skb );

#endif /* _WG_DEVICE_H */
