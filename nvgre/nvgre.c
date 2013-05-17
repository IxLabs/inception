/*
 * nvgre: Network Virtualization using Generic Routing Encapsulation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/rculist.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/hash.h>
#include <linux/ethtool.h>
#include <net/arp.h>
#include <net/ndisc.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/gre.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#define NVGRE_VERSION	"0.1"

#define VNI_HASH_BITS	10
#define VNI_HASH_SIZE	(1<<VNI_HASH_BITS)
#define FDB_HASH_BITS	8
#define FDB_HASH_SIZE	(1<<FDB_HASH_BITS)
#define FDB_AGE_DEFAULT 300 /* 5 min */
#define FDB_AGE_INTERVAL (10 * HZ)	/* rescan interval */

#define NVGRE_N_VID	(1u << 24)
#define NVGRE_VID_MASK	(NVGRE_N_VID - 1)
/* IP header + nvgre + Ethernet header */
#define NVGRE_HEADROOM (20 + 8 + 14)
/* struct nvgrehdr.nv_flags required value. 
 * KEY_BIT set and VERSION = 2
 */
#define NVGRE_FLAGS 0x2002

/* nvgre protocol header */
struct nvgrehdr {
	__be16 nv_flags;
	__be16 nv_protocol;
	__be32 nv_key;
};

static bool log_ecn_error = true;
module_param(log_ecn_error, bool, 0644);
MODULE_PARM_DESC(log_ecn_error, "Log packets received with corrupted ECN");

/* per-net private data for this module */
static unsigned int nvgre_net_id;
struct nvgre_net {
	struct socket	  *sock;	/* UDP encap socket */
	struct hlist_head vni_list[VNI_HASH_SIZE];
};

struct nvgre_rdst {
	struct rcu_head		 rcu;
	__be32			 remote_ip;
	u32			 remote_vni;
	u32			 remote_ifindex;
	struct nvgre_rdst	*remote_next;
};

/* Forwarding table entry */
struct nvgre_fdb {
	struct hlist_node hlist;	/* linked list of entries */
	struct rcu_head	  rcu;
	unsigned long	  updated;	/* jiffies */
	unsigned long	  used;
	struct nvgre_rdst remote;
	u16		  state;	/* see ndm_state */
	u8		  flags;	/* see ndm_flags */
	u8		  eth_addr[ETH_ALEN];
};

/* Pseudo network device */
struct nvgre_dev {
	struct hlist_node hlist;
	struct net_device *dev;
	struct nvgre_rdst default_dst;	/* default destination */
	__be32		  saddr;	/* source address */
	__u8		  tos;		/* TOS override */
	__u8		  ttl;
	u32		  flags;	/* nvgre_F_* below */

	unsigned long	  age_interval;
	struct timer_list age_timer;
	spinlock_t	  hash_lock;
	unsigned int	  addrcnt;
	unsigned int	  addrmax;

	struct hlist_head fdb_head[FDB_HASH_SIZE];
};

#define NVGRE_F_LEARN	0x01
#define NVGRE_F_PROXY	0x02
#define NVGRE_F_RSC	0x04
#define NVGRE_F_L2MISS	0x08
#define NVGRE_F_L3MISS	0x10

/* salt for hash table */
static u32 nvgre_salt __read_mostly;

static inline struct hlist_head *vni_head(struct net *net, u32 id)
{
	struct nvgre_net *vn = net_generic(net, nvgre_net_id);

	return &vn->vni_list[hash_32(id, VNI_HASH_BITS)];
}

/* Look up VNI in a per net namespace table */
static struct nvgre_dev *nvgre_find_vni(struct net *net, u32 id)
{
	struct nvgre_dev *nvgre;

	hlist_for_each_entry_rcu(nvgre, vni_head(net, id), hlist) {
		if (nvgre->default_dst.remote_vni == id)
			return nvgre;
	}

	return NULL;
}

/* Fill in neighbour message in skbuff. */
static int nvgre_fdb_info(struct sk_buff *skb, struct nvgre_dev *nvgre,
			   const struct nvgre_fdb *fdb,
			   u32 portid, u32 seq, int type, unsigned int flags,
			   const struct nvgre_rdst *rdst)
{
	unsigned long now = jiffies;
	struct nda_cacheinfo ci;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	bool send_ip, send_eth;

	nlh = nlmsg_put(skb, portid, seq, type, sizeof(*ndm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	memset(ndm, 0, sizeof(*ndm));

	send_eth = send_ip = true;

	if (type == RTM_GETNEIGH) {
		ndm->ndm_family	= AF_INET;
		send_ip = rdst->remote_ip != htonl(INADDR_ANY);
		send_eth = !is_zero_ether_addr(fdb->eth_addr);
	} else
		ndm->ndm_family	= AF_BRIDGE;
	ndm->ndm_state = fdb->state;
	ndm->ndm_ifindex = nvgre->dev->ifindex;
	ndm->ndm_flags = fdb->flags;
	ndm->ndm_type = NDA_DST;

	if (send_eth && nla_put(skb, NDA_LLADDR, ETH_ALEN, &fdb->eth_addr))
		goto nla_put_failure;

	if (send_ip && nla_put_be32(skb, NDA_DST, rdst->remote_ip))
		goto nla_put_failure;

	if (rdst->remote_vni != nvgre->default_dst.remote_vni &&
	    nla_put_be32(skb, NDA_VNI, rdst->remote_vni))
		goto nla_put_failure;
	if (rdst->remote_ifindex &&
	    nla_put_u32(skb, NDA_IFINDEX, rdst->remote_ifindex))
		goto nla_put_failure;

	ci.ndm_used	 = jiffies_to_clock_t(now - fdb->used);
	ci.ndm_confirmed = 0;
	ci.ndm_updated	 = jiffies_to_clock_t(now - fdb->updated);
	ci.ndm_refcnt	 = 0;

	if (nla_put(skb, NDA_CACHEINFO, sizeof(ci), &ci))
		goto nla_put_failure;

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static inline size_t nvgre_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ndmsg))
		+ nla_total_size(ETH_ALEN) /* NDA_LLADDR */
		+ nla_total_size(sizeof(__be32)) /* NDA_DST */
		+ nla_total_size(sizeof(__be32)) /* NDA_VNI */
		+ nla_total_size(sizeof(__u32)) /* NDA_IFINDEX */
		+ nla_total_size(sizeof(struct nda_cacheinfo));
}

static void nvgre_fdb_notify(struct nvgre_dev *nvgre,
			     const struct nvgre_fdb *fdb, int type)
{
	struct net *net = dev_net(nvgre->dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(nvgre_nlmsg_size(), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = nvgre_fdb_info(skb, nvgre, fdb, 0, 0, type, 0, &fdb->remote);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in nvgre_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}

	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_ATOMIC);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}

static void nvgre_ip_miss(struct net_device *dev, __be32 ipa)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct nvgre_fdb f;

	memset(&f, 0, sizeof f);
	f.state = NUD_STALE;
	f.remote.remote_ip = ipa; /* goes to NDA_DST */
	f.remote.remote_vni = NVGRE_N_VID;

	nvgre_fdb_notify(nvgre, &f, RTM_GETNEIGH);
}

static void nvgre_fdb_miss(struct nvgre_dev *nvgre, const u8 eth_addr[ETH_ALEN])
{
	struct nvgre_fdb	f;

	memset(&f, 0, sizeof f);
	f.state = NUD_STALE;
	memcpy(f.eth_addr, eth_addr, ETH_ALEN);

	nvgre_fdb_notify(nvgre, &f, RTM_GETNEIGH);
}

/* Hash Ethernet address */
static u32 eth_hash(const unsigned char *addr)
{
	u64 value = get_unaligned((u64 *)addr);

	/* only want 6 bytes */
#ifdef __BIG_ENDIAN
	value >>= 16;
#else
	value <<= 16;
#endif
	return hash_64(value, FDB_HASH_BITS);
}

/* Hash chain to use given mac address */
static inline struct hlist_head *nvgre_fdb_head(struct nvgre_dev *nvgre,
						const u8 *mac)
{
	return &nvgre->fdb_head[eth_hash(mac)];
}

/* Look up Ethernet address in forwarding table */
static struct nvgre_fdb *nvgre_find_mac(struct nvgre_dev *nvgre,
					const u8 *mac)

{
	struct hlist_head *head = nvgre_fdb_head(nvgre, mac);
	struct nvgre_fdb *f;

	hlist_for_each_entry_rcu(f, head, hlist) {
		if (compare_ether_addr(mac, f->eth_addr) == 0)
			return f;
	}

	return NULL;
}

/* Add/update destinations for multicast */
static int nvgre_fdb_append(struct nvgre_fdb *f,
			    __be32 ip, __u32 vni, __u32 ifindex)
{
	struct nvgre_rdst *rd_prev, *rd;

	rd_prev = NULL;
	for (rd = &f->remote; rd; rd = rd->remote_next) {
		if (rd->remote_ip == ip &&
		    rd->remote_vni == vni &&
		    rd->remote_ifindex == ifindex)
			return 0;
		rd_prev = rd;
	}
	rd = kmalloc(sizeof(*rd), GFP_ATOMIC);
	if (rd == NULL)
		return -ENOBUFS;
	rd->remote_ip = ip;
	rd->remote_vni = vni;
	rd->remote_ifindex = ifindex;
	rd->remote_next = NULL;
	rd_prev->remote_next = rd;
	return 1;
}

/* Add new entry to forwarding table -- assumes lock held */
static int nvgre_fdb_create(struct nvgre_dev *nvgre,
			    const u8 *mac, __be32 ip,
			    __u16 state, __u16 flags,
			    __u32 vni, __u32 ifindex,
			    __u8 ndm_flags)
{
	struct nvgre_fdb *f;
	int notify = 0;

	f = nvgre_find_mac(nvgre, mac);
	if (f) {
		if (flags & NLM_F_EXCL) {
			netdev_dbg(nvgre->dev,
				   "lost race to create %pM\n", mac);
			return -EEXIST;
		}
		if (f->state != state) {
			f->state = state;
			f->updated = jiffies;
			notify = 1;
		}
		if (f->flags != ndm_flags) {
			f->flags = ndm_flags;
			f->updated = jiffies;
			notify = 1;
		}
		if ((flags & NLM_F_APPEND) &&
		    is_multicast_ether_addr(f->eth_addr)) {
			int rc = nvgre_fdb_append(f, ip, vni, ifindex);

			if (rc < 0)
				return rc;
			notify |= rc;
		}
	} else {
		if (!(flags & NLM_F_CREATE))
			return -ENOENT;

		if (nvgre->addrmax && nvgre->addrcnt >= nvgre->addrmax)
			return -ENOSPC;

		netdev_dbg(nvgre->dev, "add %pM -> %pI4\n", mac, &ip);
		f = kmalloc(sizeof(*f), GFP_ATOMIC);
		if (!f)
			return -ENOMEM;

		notify = 1;
		f->remote.remote_ip = ip;
		f->remote.remote_vni = vni;
		f->remote.remote_ifindex = ifindex;
		f->remote.remote_next = NULL;
		f->state = state;
		f->flags = ndm_flags;
		f->updated = f->used = jiffies;
		memcpy(f->eth_addr, mac, ETH_ALEN);

		++nvgre->addrcnt;
		hlist_add_head_rcu(&f->hlist,
				   nvgre_fdb_head(nvgre, mac));
	}

	if (notify)
		nvgre_fdb_notify(nvgre, f, RTM_NEWNEIGH);

	return 0;
}

static void nvgre_fdb_free(struct rcu_head *head)
{
	struct nvgre_fdb *f = container_of(head, struct nvgre_fdb, rcu);

	while (f->remote.remote_next) {
		struct nvgre_rdst *rd = f->remote.remote_next;

		f->remote.remote_next = rd->remote_next;
		kfree(rd);
	}
	kfree(f);
}

static void nvgre_fdb_destroy(struct nvgre_dev *nvgre, struct nvgre_fdb *f)
{
	netdev_dbg(nvgre->dev,
		    "delete %pM\n", f->eth_addr);

	--nvgre->addrcnt;
	nvgre_fdb_notify(nvgre, f, RTM_DELNEIGH);

	hlist_del_rcu(&f->hlist);
	call_rcu(&f->rcu, nvgre_fdb_free);
}

/* Add static entry (via netlink) */
static int nvgre_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			 struct net_device *dev,
			 const unsigned char *addr, u16 flags)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct net *net = dev_net(nvgre->dev);
	__be32 ip;
	u32 vni, ifindex;
	int err;

	if (!(ndm->ndm_state & (NUD_PERMANENT|NUD_REACHABLE))) {
		pr_info("RTM_NEWNEIGH with invalid state %#x\n",
			ndm->ndm_state);
		return -EINVAL;
	}

	if (tb[NDA_DST] == NULL)
		return -EINVAL;

	if (nla_len(tb[NDA_DST]) != sizeof(__be32))
		return -EAFNOSUPPORT;

	ip = nla_get_be32(tb[NDA_DST]);

	if (tb[NDA_VNI]) {
		if (nla_len(tb[NDA_VNI]) != sizeof(u32))
			return -EINVAL;
		vni = nla_get_u32(tb[NDA_VNI]);
	} else
		vni = nvgre->default_dst.remote_vni;

	if (tb[NDA_IFINDEX]) {
		struct net_device *tdev;

		if (nla_len(tb[NDA_IFINDEX]) != sizeof(u32))
			return -EINVAL;
		ifindex = nla_get_u32(tb[NDA_IFINDEX]);
		tdev = dev_get_by_index(net, ifindex);
		if (!tdev)
			return -EADDRNOTAVAIL;
		dev_put(tdev);
	} else
		ifindex = 0;

	spin_lock_bh(&nvgre->hash_lock);
	err = nvgre_fdb_create(nvgre, addr, ip, ndm->ndm_state, flags,
			       vni, ifindex, ndm->ndm_flags);
	spin_unlock_bh(&nvgre->hash_lock);

	return err;
}

/* Delete entry (via netlink) */
static int nvgre_fdb_delete(struct ndmsg *ndm, struct nlattr *tb[],
			    struct net_device *dev,
			    const unsigned char *addr)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct nvgre_fdb *f;
	int err = -ENOENT;

	spin_lock_bh(&nvgre->hash_lock);
	f = nvgre_find_mac(nvgre, addr);
	if (f) {
		nvgre_fdb_destroy(nvgre, f);
		err = 0;
	}
	spin_unlock_bh(&nvgre->hash_lock);

	return err;
}

/* Dump forwarding table */
static int nvgre_fdb_dump(struct sk_buff *skb, struct netlink_callback *cb,
			  struct net_device *dev, int idx)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	unsigned int h;

	for (h = 0; h < FDB_HASH_SIZE; ++h) {
		struct nvgre_fdb *f;
		int err;

		hlist_for_each_entry_rcu(f, &nvgre->fdb_head[h], hlist) {
			struct nvgre_rdst *rd;
			for (rd = &f->remote; rd; rd = rd->remote_next) {
				if (idx < cb->args[0])
					goto skip;

				err = nvgre_fdb_info(skb, nvgre, f,
						     NETLINK_CB(cb->skb).portid,
						     cb->nlh->nlmsg_seq,
						     RTM_NEWNEIGH,
						     NLM_F_MULTI, rd);
				if (err < 0)
					break;
skip:
				++idx;
			}
		}
	}

	return idx;
}

/* Watch incoming packets to learn mapping between Ethernet address
 * and Tunnel endpoint.
 */
static void nvgre_snoop(struct net_device *dev,
			__be32 src_ip, const u8 *src_mac)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct nvgre_fdb *f;
	int err;

	f = nvgre_find_mac(nvgre, src_mac);
	if (likely(f)) {
		f->used = jiffies;
		if (likely(f->remote.remote_ip == src_ip))
			return;

		if (net_ratelimit())
			netdev_info(dev,
				    "%pM migrated from %pI4 to %pI4\n",
				    src_mac, &f->remote.remote_ip, &src_ip);

		f->remote.remote_ip = src_ip;
		f->updated = jiffies;
	} else {
		/* learned new entry */
		spin_lock(&nvgre->hash_lock);
		err = nvgre_fdb_create(nvgre, src_mac, src_ip,
				       NUD_REACHABLE,
				       NLM_F_EXCL|NLM_F_CREATE,
				       nvgre->default_dst.remote_vni,
				       0, NTF_SELF);
		spin_unlock(&nvgre->hash_lock);
	}
}


/* See if multicast group is already in use by other ID */
static bool nvgre_group_used(struct nvgre_net *vn,
			     const struct nvgre_dev *this)
{
	const struct nvgre_dev *nvgre;
	unsigned h;

	for (h = 0; h < VNI_HASH_SIZE; ++h)
		hlist_for_each_entry(nvgre, &vn->vni_list[h], hlist) {
			if (nvgre == this)
				continue;

			if (!netif_running(nvgre->dev))
				continue;

			if (nvgre->default_dst.remote_ip == this->default_dst.remote_ip)
				return true;
		}

	return false;
}

/* kernel equivalent to IP_ADD_MEMBERSHIP */
static int nvgre_join_group(struct net_device *dev)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct nvgre_net *vn = net_generic(dev_net(dev), nvgre_net_id);
	struct sock *sk = vn->sock->sk;
	struct ip_mreqn mreq = {
		.imr_multiaddr.s_addr	= nvgre->default_dst.remote_ip,
		.imr_ifindex		= nvgre->default_dst.remote_ifindex,
	};
	int err;

	/* Already a member of group */
	if (nvgre_group_used(vn, nvgre))
		return 0;

	/* Need to drop RTNL to call multicast join */
	rtnl_unlock();
	lock_sock(sk);
	err = ip_mc_join_group(sk, &mreq);
	release_sock(sk);
	rtnl_lock();

	return err;
}


/* kernel equivalent to IP_DROP_MEMBERSHIP */
static int nvgre_leave_group(struct net_device *dev)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct nvgre_net *vn = net_generic(dev_net(dev), nvgre_net_id);
	int err = 0;
	struct sock *sk = vn->sock->sk;
	struct ip_mreqn mreq = {
		.imr_multiaddr.s_addr	= nvgre->default_dst.remote_ip,
		.imr_ifindex		= nvgre->default_dst.remote_ifindex,
	};

	/* Only leave group when last nvgre is done. */
	if (nvgre_group_used(vn, nvgre))
		return 0;

	/* Need to drop RTNL to call multicast leave */
	rtnl_unlock();
	lock_sock(sk);
	err = ip_mc_leave_group(sk, &mreq);
	release_sock(sk);
	rtnl_lock();

	return err;
}

static int nvgre_rcv(struct sk_buff *skb)
{
	struct nvgrehdr *grehdr;
	struct nvgre_dev *nvgre;
	struct iphdr *oip;
	struct pcpu_tstats *stats;
	__u32 vsn;
	int err;

	if (!pskb_may_pull(skb, sizeof(*grehdr)))
		goto drop;

	grehdr = skb->data;
	vsn = htonl(grehdr->nv_key << 8) & 0xffffff;

	__skb_pull(skb, sizeof(struct nvgrehdr));

	printk(KERN_CRIT "nvgre_rcv packet, vsn=%d\n", vsn);
	nvgre = nvgre_find_vni(&init_net, vsn);
	if (!nvgre) {
		netdev_dbg(skb->dev, "unknown vni %d\n", vsn);
		goto drop;
	}
	printk(KERN_CRIT "found nvgre device for vni %d\n", vsn);

	if (!pskb_may_pull(skb, ETH_HLEN)) {
		nvgre->dev->stats.rx_length_errors++;
		nvgre->dev->stats.rx_errors++;
		goto drop;
	}

	skb_reset_mac_header(skb);

	/* Re-examine inner Ethernet packet */
	oip = ip_hdr(skb);
	skb->protocol = eth_type_trans(skb, nvgre->dev);

	/* Ignore packet loops (and multicast echo) */
	if (compare_ether_addr(eth_hdr(skb)->h_source,
			       nvgre->dev->dev_addr) == 0)
		goto drop;

	if (nvgre->flags & NVGRE_F_LEARN)
		nvgre_snoop(skb->dev, oip->saddr, eth_hdr(skb)->h_source);

	__skb_tunnel_rx(skb, nvgre->dev);
	skb_reset_network_header(skb);

	/* If the NIC driver gave us an encapsulated packet with
	 * CHECKSUM_UNNECESSARY and Rx checksum feature is enabled,
	 * leave the CHECKSUM_UNNECESSARY, the device checksummed it
	 * for us. Otherwise force the upper layers to verify it.
	 */
	if (skb->ip_summed != CHECKSUM_UNNECESSARY || !skb->encapsulation ||
	    !(nvgre->dev->features & NETIF_F_RXCSUM))
		skb->ip_summed = CHECKSUM_NONE;

	skb->encapsulation = 0;

	err = IP_ECN_decapsulate(oip, skb);
	if (unlikely(err)) {
		if (log_ecn_error)
			net_info_ratelimited("non-ECT from %pI4 with TOS=%#x\n",
					     &oip->saddr, oip->tos);
		if (err > 1) {
			++nvgre->dev->stats.rx_frame_errors;
			++nvgre->dev->stats.rx_errors;
			goto drop;
		}
	}

	stats = this_cpu_ptr(nvgre->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netif_rx(skb);
	printk(KERN_CRIT "netif_rx done\n");
	return NET_RX_SUCCESS;
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
#if 0
/* Callback from net/ipv4/udp.c to receive packets */
static int nvgre_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct iphdr *oip;
	struct nvgrehdr *vxh;
	struct nvgre_dev *nvgre;
	struct pcpu_tstats *stats;
	__u32 vni;
	int err;

	/* pop off outer UDP header */
	__skb_pull(skb, sizeof(struct udphdr));

	/* Need nvgre and inner Ethernet header to be present */
	if (!pskb_may_pull(skb, sizeof(struct nvgrehdr)))
		goto error;

	/* Drop packets with reserved bits set */
	vxh = (struct nvgrehdr *) skb->data;
	if (vxh->nv_flags != htonl(NVGRE_FLAGS) ||
	    (vxh->nv_key & htonl(0xff))) {
		netdev_dbg(skb->dev, "invalid nvgre flags=%#x vni=%#x\n",
			   ntohl(vxh->nv_flags), ntohl(vxh->nv_key));
		goto error;
	}

	__skb_pull(skb, sizeof(struct nvgrehdr));

	/* Is this VNI defined? */
	vni = ntohl(vxh->nv_key) >> 8;
	nvgre = nvgre_find_vni(sock_net(sk), vni);
	if (!nvgre) {
		netdev_dbg(skb->dev, "unknown vni %d\n", vni);
		goto drop;
	}

	if (!pskb_may_pull(skb, ETH_HLEN)) {
		nvgre->dev->stats.rx_length_errors++;
		nvgre->dev->stats.rx_errors++;
		goto drop;
	}

	skb_reset_mac_header(skb);

	/* Re-examine inner Ethernet packet */
	oip = ip_hdr(skb);
	skb->protocol = eth_type_trans(skb, nvgre->dev);

	/* Ignore packet loops (and multicast echo) */
	if (compare_ether_addr(eth_hdr(skb)->h_source,
			       nvgre->dev->dev_addr) == 0)
		goto drop;

	if (nvgre->flags & NVGRE_F_LEARN)
		nvgre_snoop(skb->dev, oip->saddr, eth_hdr(skb)->h_source);

	__skb_tunnel_rx(skb, nvgre->dev);
	skb_reset_network_header(skb);

	/* If the NIC driver gave us an encapsulated packet with
	 * CHECKSUM_UNNECESSARY and Rx checksum feature is enabled,
	 * leave the CHECKSUM_UNNECESSARY, the device checksummed it
	 * for us. Otherwise force the upper layers to verify it.
	 */
	if (skb->ip_summed != CHECKSUM_UNNECESSARY || !skb->encapsulation ||
	    !(nvgre->dev->features & NETIF_F_RXCSUM))
		skb->ip_summed = CHECKSUM_NONE;

	skb->encapsulation = 0;

	err = IP_ECN_decapsulate(oip, skb);
	if (unlikely(err)) {
		if (log_ecn_error)
			net_info_ratelimited("non-ECT from %pI4 with TOS=%#x\n",
					     &oip->saddr, oip->tos);
		if (err > 1) {
			++nvgre->dev->stats.rx_frame_errors;
			++nvgre->dev->stats.rx_errors;
			goto drop;
		}
	}

	stats = this_cpu_ptr(nvgre->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netif_rx(skb);

	return 0;
error:
	/* Put UDP header back */
	__skb_push(skb, sizeof(struct udphdr));

	return 1;
drop:
	/* Consume bad packet */
	kfree_skb(skb);
	return 0;
}
#endif
static int arp_reduce(struct net_device *dev, struct sk_buff *skb)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct arphdr *parp;
	u8 *arpptr, *sha;
	__be32 sip, tip;
	struct neighbour *n;

	if (dev->flags & IFF_NOARP)
		goto out;

	if (!pskb_may_pull(skb, arp_hdr_len(dev))) {
		dev->stats.tx_dropped++;
		goto out;
	}
	parp = arp_hdr(skb);

	if ((parp->ar_hrd != htons(ARPHRD_ETHER) &&
	     parp->ar_hrd != htons(ARPHRD_IEEE802)) ||
	    parp->ar_pro != htons(ETH_P_IP) ||
	    parp->ar_op != htons(ARPOP_REQUEST) ||
	    parp->ar_hln != dev->addr_len ||
	    parp->ar_pln != 4)
		goto out;
	arpptr = (u8 *)parp + sizeof(struct arphdr);
	sha = arpptr;
	arpptr += dev->addr_len;	/* sha */
	memcpy(&sip, arpptr, sizeof(sip));
	arpptr += sizeof(sip);
	arpptr += dev->addr_len;	/* tha */
	memcpy(&tip, arpptr, sizeof(tip));

	if (ipv4_is_loopback(tip) ||
	    ipv4_is_multicast(tip))
		goto out;

	n = neigh_lookup(&arp_tbl, &tip, dev);

	if (n) {
		struct nvgre_fdb *f;
		struct sk_buff	*reply;

		if (!(n->nud_state & NUD_CONNECTED)) {
			neigh_release(n);
			goto out;
		}

		f = nvgre_find_mac(nvgre, n->ha);
		if (f && f->remote.remote_ip == htonl(INADDR_ANY)) {
			/* bridge-local neighbor */
			neigh_release(n);
			goto out;
		}

		reply = arp_create(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, sha,
				n->ha, sha);

		neigh_release(n);

		skb_reset_mac_header(reply);
		__skb_pull(reply, skb_network_offset(reply));
		reply->ip_summed = CHECKSUM_UNNECESSARY;
		reply->pkt_type = PACKET_HOST;

		if (netif_rx_ni(reply) == NET_RX_DROP)
			dev->stats.rx_dropped++;
	} else if (nvgre->flags & NVGRE_F_L3MISS)
		nvgre_ip_miss(dev, tip);
out:
	consume_skb(skb);
	return NETDEV_TX_OK;
}

static bool route_shortcircuit(struct net_device *dev, struct sk_buff *skb)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct neighbour *n;
	struct iphdr *pip;

	if (is_multicast_ether_addr(eth_hdr(skb)->h_dest))
		return false;

	n = NULL;
	switch (ntohs(eth_hdr(skb)->h_proto)) {
	case ETH_P_IP:
		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return false;
		pip = ip_hdr(skb);
		n = neigh_lookup(&arp_tbl, &pip->daddr, dev);
		break;
	default:
		return false;
	}

	if (n) {
		bool diff;

		diff = compare_ether_addr(eth_hdr(skb)->h_dest, n->ha) != 0;
		if (diff) {
			memcpy(eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest,
				dev->addr_len);
			memcpy(eth_hdr(skb)->h_dest, n->ha, dev->addr_len);
		}
		neigh_release(n);
		return diff;
	} else if (nvgre->flags & NVGRE_F_L3MISS)
		nvgre_ip_miss(dev, pip->daddr);
	return false;
}

static void nvgre_sock_free(struct sk_buff *skb)
{
	sock_put(skb->sk);
}

/* On transmit, associate with the tunnel socket */
static void nvgre_set_owner(struct net_device *dev, struct sk_buff *skb)
{
	struct nvgre_net *vn = net_generic(dev_net(dev), nvgre_net_id);
	struct sock *sk = vn->sock->sk;

	skb_orphan(skb);
	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = nvgre_sock_free;
}

static int handle_offloads(struct sk_buff *skb)
{
	if (skb_is_gso(skb)) {
		int err = skb_unclone(skb, GFP_ATOMIC);
		if (unlikely(err))
			return err;

		skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL;
	} else if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_NONE;

	return 0;
}

/* Bypass encapsulation if the destination is local */
static void nvgre_encap_bypass(struct sk_buff *skb, struct nvgre_dev *src_nvgre,
			       struct nvgre_dev *dst_nvgre)
{
	struct pcpu_tstats *tx_stats = this_cpu_ptr(src_nvgre->dev->tstats);
	struct pcpu_tstats *rx_stats = this_cpu_ptr(dst_nvgre->dev->tstats);

	skb->pkt_type = PACKET_HOST;
	skb->encapsulation = 0;
	skb->dev = dst_nvgre->dev;
	__skb_pull(skb, skb_network_offset(skb));

	if (dst_nvgre->flags & NVGRE_F_LEARN)
		nvgre_snoop(skb->dev, htonl(INADDR_LOOPBACK),
			    eth_hdr(skb)->h_source);

	u64_stats_update_begin(&tx_stats->syncp);
	tx_stats->tx_packets++;
	tx_stats->tx_bytes += skb->len;
	u64_stats_update_end(&tx_stats->syncp);

	if (netif_rx(skb) == NET_RX_SUCCESS) {
		u64_stats_update_begin(&rx_stats->syncp);
		rx_stats->rx_packets++;
		rx_stats->rx_bytes += skb->len;
		u64_stats_update_end(&rx_stats->syncp);
	} else {
		skb->dev->stats.rx_dropped++;
	}
}

static netdev_tx_t nvgre_xmit_one(struct sk_buff *skb, struct net_device *dev,
				  struct nvgre_rdst *rdst, bool did_rsc)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct rtable *rt;
	const struct iphdr *old_iph;
	struct iphdr *iph;
	struct nvgrehdr *vxh;
	struct flowi4 fl4;
	__be32 dst;
        u32 vni;
	__be16 df = 0;
	__u8 tos, ttl;

	vni = rdst->remote_vni;
	dst = rdst->remote_ip;

	printk(KERN_CRIT "nvgre xmit one vni=%d remote_ip=%pI4\n", vni, &dst);

	if (!dst) {
		if (did_rsc) {
			/* short-circuited back to local bridge */
			nvgre_encap_bypass(skb, nvgre, nvgre);
			return NETDEV_TX_OK;
		}
		goto drop;
	}

	if (!skb->encapsulation) {
		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;
	}

	/* Need space for new headers (invalidates iph ptr) */
	if (skb_cow_head(skb, NVGRE_HEADROOM))
		goto drop;
	printk(KERN_CRIT "cow head\n");

	old_iph = ip_hdr(skb);

	ttl = nvgre->ttl;
	if (!ttl && IN_MULTICAST(ntohl(dst)))
		ttl = 1;

	tos = nvgre->tos;
	if (tos == 1)
		tos = ip_tunnel_get_dsfield(old_iph, skb);

	memset(&fl4, 0, sizeof(fl4));
	fl4.flowi4_oif = rdst->remote_ifindex;
	fl4.flowi4_tos = RT_TOS(tos);
	fl4.daddr = dst;
	fl4.saddr = nvgre->saddr;

	rt = ip_route_output_key(dev_net(dev), &fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(dev, "no route to %pI4\n", &dst);
		printk(KERN_CRIT "no route to %pI4 oif %d\n", &dst, rdst->remote_ifindex);
		dev->stats.tx_carrier_errors++;
		goto tx_error;
	}

	if (rt->dst.dev == dev) {
		netdev_dbg(dev, "circular route to %pI4\n", &dst);
		printk(KERN_CRIT "circular route\n");
		ip_rt_put(rt);
		dev->stats.collisions++;
		goto tx_error;
	}
	printk(KERN_CRIT "before bypass\n");

	/* Bypass encapsulation if the destination is local */
	if (rt->rt_flags & RTCF_LOCAL &&
	    !(rt->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))) {
		struct nvgre_dev *dst_nvgre;

		ip_rt_put(rt);
		dst_nvgre = nvgre_find_vni(dev_net(dev), vni);
		if (!dst_nvgre)
			goto tx_error;
		nvgre_encap_bypass(skb, nvgre, dst_nvgre);
		return NETDEV_TX_OK;
	}

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);

	vxh = (struct nvgrehdr *) __skb_push(skb, sizeof(*vxh));
	vxh->nv_flags = htons(NVGRE_FLAGS);
	vxh->nv_key = htonl(vni) >> 8;
	vxh->nv_protocol = htons(ETH_P_TEB);

	__skb_push(skb, sizeof(*iph));
	skb_reset_network_header(skb);
	iph		= ip_hdr(skb);
	iph->version	= 4;
	iph->ihl	= sizeof(struct iphdr) >> 2;
	iph->frag_off	= df;
	iph->protocol	= IPPROTO_GRE;
	iph->tos	= ip_tunnel_ecn_encap(tos, old_iph, skb);
	iph->daddr	= dst;
	iph->saddr	= fl4.saddr;
	iph->ttl	= ttl ? : ip4_dst_hoplimit(&rt->dst);
	tunnel_ip_select_ident(skb, old_iph, &rt->dst);

	nf_reset(skb);

	nvgre_set_owner(dev, skb);

	printk(KERN_CRIT "offload\n");
	if (handle_offloads(skb))
		goto drop;

	printk(KERN_CRIT "xmiting ok\n");
	iptunnel_xmit(skb, dev);
	return NETDEV_TX_OK;

drop:
	dev->stats.tx_dropped++;
	goto tx_free;

tx_error:
	dev->stats.tx_errors++;
tx_free:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/* Transmit local packets over nvgre
 *
 * Outer IP header inherits ECN and DF from inner header.
 * Outer UDP destination is the nvgre assigned port.
 *           source port is based on hash of flow
 */
static netdev_tx_t nvgre_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct ethhdr *eth;
	bool did_rsc = false;
	struct nvgre_rdst *rdst0, *rdst;
	struct nvgre_fdb *f;
	int rc1, rc;

	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);

	printk(KERN_CRIT "nvgre xmit\n");

	//if ((nvgre->flags & NVGRE_F_PROXY) && ntohs(eth->h_proto) == ETH_P_ARP)
	//	return arp_reduce(dev, skb);

	f = nvgre_find_mac(nvgre, eth->h_dest);
	did_rsc = false;
	printk(KERN_CRIT "f = %p\n", f);
	//if (f && (f->flags & NTF_ROUTER) && (nvgre->flags & NVGRE_F_RSC) &&
	//    ntohs(eth->h_proto) == ETH_P_IP) {
	//	did_rsc = route_shortcircuit(dev, skb);
	//	if (did_rsc)
	//		f = nvgre_find_mac(nvgre, eth->h_dest);
	//}

	if (f == NULL) {
		rdst0 = &nvgre->default_dst;

		if (rdst0->remote_ip == htonl(INADDR_ANY) &&
		    (nvgre->flags & NVGRE_F_L2MISS) &&
		    !is_multicast_ether_addr(eth->h_dest))
			nvgre_fdb_miss(nvgre, eth->h_dest);
	} else
		rdst0 = &f->remote;

	rc = NETDEV_TX_OK;

	/* if there are multiple destinations, send copies */
	for (rdst = rdst0->remote_next; rdst; rdst = rdst->remote_next) {
		struct sk_buff *skb1;

		skb1 = skb_clone(skb, GFP_ATOMIC);
		rc1 = nvgre_xmit_one(skb1, dev, rdst, did_rsc);
		if (rc == NETDEV_TX_OK)
			rc = rc1;
	}

	rc1 = nvgre_xmit_one(skb, dev, rdst0, did_rsc);
	if (rc == NETDEV_TX_OK)
		rc = rc1;
	return rc;
}

/* Walk the forwarding table and purge stale entries */
static void nvgre_cleanup(unsigned long arg)
{
	struct nvgre_dev *nvgre = (struct nvgre_dev *) arg;
	unsigned long next_timer = jiffies + FDB_AGE_INTERVAL;
	unsigned int h;

	if (!netif_running(nvgre->dev))
		return;

	spin_lock_bh(&nvgre->hash_lock);
	for (h = 0; h < FDB_HASH_SIZE; ++h) {
		struct hlist_node *p, *n;
		hlist_for_each_safe(p, n, &nvgre->fdb_head[h]) {
			struct nvgre_fdb *f
				= container_of(p, struct nvgre_fdb, hlist);
			unsigned long timeout;

			if (f->state & NUD_PERMANENT)
				continue;

			timeout = f->used + nvgre->age_interval * HZ;
			if (time_before_eq(timeout, jiffies)) {
				netdev_dbg(nvgre->dev,
					   "garbage collect %pM\n",
					   f->eth_addr);
				f->state = NUD_STALE;
				nvgre_fdb_destroy(nvgre, f);
			} else if (time_before(timeout, next_timer))
				next_timer = timeout;
		}
	}
	spin_unlock_bh(&nvgre->hash_lock);

	mod_timer(&nvgre->age_timer, next_timer);
}

/* Setup stats when device is created */
static int nvgre_init(struct net_device *dev)
{
	dev->tstats = alloc_percpu(struct pcpu_tstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

/* Start ageing timer and join group when device is brought up */
static int nvgre_open(struct net_device *dev)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	int err;

	if (IN_MULTICAST(ntohl(nvgre->default_dst.remote_ip))) {
		err = nvgre_join_group(dev);
		if (err)
			return err;
	}

	if (nvgre->age_interval)
		mod_timer(&nvgre->age_timer, jiffies + FDB_AGE_INTERVAL);

	return 0;
}

/* Purge the forwarding table */
static void nvgre_flush(struct nvgre_dev *nvgre)
{
	unsigned h;

	spin_lock_bh(&nvgre->hash_lock);
	for (h = 0; h < FDB_HASH_SIZE; ++h) {
		struct hlist_node *p, *n;
		hlist_for_each_safe(p, n, &nvgre->fdb_head[h]) {
			struct nvgre_fdb *f
				= container_of(p, struct nvgre_fdb, hlist);
			nvgre_fdb_destroy(nvgre, f);
		}
	}
	spin_unlock_bh(&nvgre->hash_lock);
}

/* Cleanup timer and forwarding table on shutdown */
static int nvgre_stop(struct net_device *dev)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);

	if (IN_MULTICAST(ntohl(nvgre->default_dst.remote_ip)))
		nvgre_leave_group(dev);

	del_timer_sync(&nvgre->age_timer);

	nvgre_flush(nvgre);

	return 0;
}

/* Stub, nothing needs to be done. */
static void nvgre_set_multicast_list(struct net_device *dev)
{
}

static const struct net_device_ops nvgre_netdev_ops = {
	.ndo_init		= nvgre_init,
	.ndo_open		= nvgre_open,
	.ndo_stop		= nvgre_stop,
	.ndo_start_xmit		= nvgre_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64,
	.ndo_set_rx_mode	= nvgre_set_multicast_list,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_fdb_add		= nvgre_fdb_add,
	.ndo_fdb_del		= nvgre_fdb_delete,
	.ndo_fdb_dump		= nvgre_fdb_dump,
};

/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type nvgre_type = {
	.name = "nvgre",
};

static void nvgre_free(struct net_device *dev)
{
	free_percpu(dev->tstats);
	free_netdev(dev);
}

/* Initialize the device structure. */
static void nvgre_setup(struct net_device *dev)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	unsigned h;

	eth_hw_addr_random(dev);
	ether_setup(dev);
	dev->hard_header_len = ETH_HLEN + NVGRE_HEADROOM;

	dev->netdev_ops = &nvgre_netdev_ops;
	dev->destructor = nvgre_free;
	SET_NETDEV_DEVTYPE(dev, &nvgre_type);

	dev->tx_queue_len = 0;
	dev->features	|= NETIF_F_LLTX;
	dev->features	|= NETIF_F_NETNS_LOCAL;
	dev->features	|= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features   |= NETIF_F_RXCSUM;
	dev->features   |= NETIF_F_GSO_SOFTWARE;

	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;
	dev->priv_flags	&= ~IFF_XMIT_DST_RELEASE;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

	spin_lock_init(&nvgre->hash_lock);

	init_timer_deferrable(&nvgre->age_timer);
	nvgre->age_timer.function = nvgre_cleanup;
	nvgre->age_timer.data = (unsigned long) nvgre;

	nvgre->dev = dev;

	for (h = 0; h < FDB_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&nvgre->fdb_head[h]);
}

static const struct nla_policy nvgre_policy[IFLA_NVGRE_MAX + 1] = {
	[IFLA_NVGRE_ID]		= { .type = NLA_U32 },
	[IFLA_NVGRE_GROUP]	= { .len = FIELD_SIZEOF(struct iphdr, daddr) },
	[IFLA_NVGRE_LINK]	= { .type = NLA_U32 },
	[IFLA_NVGRE_LOCAL]	= { .len = FIELD_SIZEOF(struct iphdr, saddr) },
	[IFLA_NVGRE_TOS]	= { .type = NLA_U8 },
	[IFLA_NVGRE_TTL]	= { .type = NLA_U8 },
	[IFLA_NVGRE_LEARNING]	= { .type = NLA_U8 },
	[IFLA_NVGRE_AGEING]	= { .type = NLA_U32 },
	[IFLA_NVGRE_LIMIT]	= { .type = NLA_U32 },
	[IFLA_NVGRE_PROXY]	= { .type = NLA_U8 },
	[IFLA_NVGRE_RSC]	= { .type = NLA_U8 },
	[IFLA_NVGRE_L2MISS]	= { .type = NLA_U8 },
	[IFLA_NVGRE_L3MISS]	= { .type = NLA_U8 },
};

static int nvgre_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {
			pr_debug("invalid link address (not ethernet)\n");
			return -EINVAL;
		}

		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {
			pr_debug("invalid all zero ethernet address\n");
			return -EADDRNOTAVAIL;
		}
	}

	if (!data)
		return -EINVAL;

	if (data[IFLA_NVGRE_ID]) {
		__u32 id = nla_get_u32(data[IFLA_NVGRE_ID]);
		if (id >= NVGRE_VID_MASK)
			return -ERANGE;
	}

	return 0;
}

static void nvgre_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->version, NVGRE_VERSION, sizeof(drvinfo->version));
	strlcpy(drvinfo->driver, "nvgre", sizeof(drvinfo->driver));
}

static const struct ethtool_ops nvgre_ethtool_ops = {
	.get_drvinfo	= nvgre_get_drvinfo,
	.get_link	= ethtool_op_get_link,
};

static int nvgre_newlink(struct net *net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[])
{
	struct nvgre_dev *nvgre = netdev_priv(dev);
	struct nvgre_rdst *dst = &nvgre->default_dst;
	__u32 vni;
	int err;

	if (!data[IFLA_NVGRE_ID])
		return -EINVAL;

	vni = nla_get_u32(data[IFLA_NVGRE_ID]);
	if (nvgre_find_vni(net, vni)) {
		pr_info("duplicate VNI %u\n", vni);
		return -EEXIST;
	}
	dst->remote_vni = vni;

	if (data[IFLA_NVGRE_GROUP])
		dst->remote_ip = nla_get_be32(data[IFLA_NVGRE_GROUP]);

	if (data[IFLA_NVGRE_LOCAL])
		nvgre->saddr = nla_get_be32(data[IFLA_NVGRE_LOCAL]);

	if (data[IFLA_NVGRE_LINK] &&
	    (dst->remote_ifindex = nla_get_u32(data[IFLA_NVGRE_LINK]))) {
		struct net_device *lowerdev
			 = __dev_get_by_index(net, dst->remote_ifindex);

		if (!lowerdev) {
			pr_info("ifindex %d does not exist\n", dst->remote_ifindex);
			return -ENODEV;
		}

		if (!tb[IFLA_MTU])
			dev->mtu = lowerdev->mtu - NVGRE_HEADROOM;

		/* update header length based on lower device */
		dev->hard_header_len = lowerdev->hard_header_len +
				       NVGRE_HEADROOM;
	}

	if (data[IFLA_NVGRE_TOS])
		nvgre->tos  = nla_get_u8(data[IFLA_NVGRE_TOS]);

	if (data[IFLA_NVGRE_TTL])
		nvgre->ttl = nla_get_u8(data[IFLA_NVGRE_TTL]);

	if (!data[IFLA_NVGRE_LEARNING] || nla_get_u8(data[IFLA_NVGRE_LEARNING]))
		nvgre->flags |= NVGRE_F_LEARN;

	if (data[IFLA_NVGRE_AGEING])
		nvgre->age_interval = nla_get_u32(data[IFLA_NVGRE_AGEING]);
	else
		nvgre->age_interval = FDB_AGE_DEFAULT;

	if (data[IFLA_NVGRE_PROXY] && nla_get_u8(data[IFLA_NVGRE_PROXY]))
		nvgre->flags |= NVGRE_F_PROXY;

	if (data[IFLA_NVGRE_RSC] && nla_get_u8(data[IFLA_NVGRE_RSC]))
		nvgre->flags |= NVGRE_F_RSC;

	if (data[IFLA_NVGRE_L2MISS] && nla_get_u8(data[IFLA_NVGRE_L2MISS]))
		nvgre->flags |= NVGRE_F_L2MISS;

	if (data[IFLA_NVGRE_L3MISS] && nla_get_u8(data[IFLA_NVGRE_L3MISS]))
		nvgre->flags |= NVGRE_F_L3MISS;

	if (data[IFLA_NVGRE_LIMIT])
		nvgre->addrmax = nla_get_u32(data[IFLA_NVGRE_LIMIT]);

	SET_ETHTOOL_OPS(dev, &nvgre_ethtool_ops);

	err = register_netdevice(dev);
	if (!err)
		hlist_add_head_rcu(&nvgre->hlist, vni_head(net, dst->remote_vni));

	return err;
}

static void nvgre_dellink(struct net_device *dev, struct list_head *head)
{
	struct nvgre_dev *nvgre = netdev_priv(dev);

	hlist_del_rcu(&nvgre->hlist);

	unregister_netdevice_queue(dev, head);
}

static size_t nvgre_get_size(const struct net_device *dev)
{

	return nla_total_size(sizeof(__u32)) +	/* IFLA_NVGRE_ID */
		nla_total_size(sizeof(__be32)) +/* IFLA_NVGRE_GROUP */
		nla_total_size(sizeof(__u32)) +	/* IFLA_NVGRE_LINK */
		nla_total_size(sizeof(__be32))+	/* IFLA_NVGRE_LOCAL */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NVGRE_TTL */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NVGRE_TOS */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NVGRE_LEARNING */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NVGRE_PROXY */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NVGRE_RSC */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NVGRE_L2MISS */
		nla_total_size(sizeof(__u8)) +	/* IFLA_NVGRE_L3MISS */
		nla_total_size(sizeof(__u32)) +	/* IFLA_NVGRE_AGEING */
		nla_total_size(sizeof(__u32)) +	/* IFLA_NVGRE_LIMIT */
		nla_total_size(sizeof(struct ifla_nvgre_port_range)) +
		nla_total_size(sizeof(__be16))+ /* IFLA_NVGRE_PORT */
		0;
}

static int nvgre_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	const struct nvgre_dev *nvgre = netdev_priv(dev);
	const struct nvgre_rdst *dst = &nvgre->default_dst;

	if (nla_put_u32(skb, IFLA_NVGRE_ID, dst->remote_vni))
		goto nla_put_failure;

	if (dst->remote_ip && nla_put_be32(skb, IFLA_NVGRE_GROUP, dst->remote_ip))
		goto nla_put_failure;

	if (dst->remote_ifindex && nla_put_u32(skb, IFLA_NVGRE_LINK, dst->remote_ifindex))
		goto nla_put_failure;

	if (nvgre->saddr && nla_put_be32(skb, IFLA_NVGRE_LOCAL, nvgre->saddr))
		goto nla_put_failure;

	if (nla_put_u8(skb, IFLA_NVGRE_TTL, nvgre->ttl) ||
	    nla_put_u8(skb, IFLA_NVGRE_TOS, nvgre->tos) ||
	    nla_put_u8(skb, IFLA_NVGRE_LEARNING,
			!!(nvgre->flags & NVGRE_F_LEARN)) ||
	    nla_put_u8(skb, IFLA_NVGRE_PROXY,
			!!(nvgre->flags & NVGRE_F_PROXY)) ||
	    nla_put_u8(skb, IFLA_NVGRE_RSC, !!(nvgre->flags & NVGRE_F_RSC)) ||
	    nla_put_u8(skb, IFLA_NVGRE_L2MISS,
			!!(nvgre->flags & NVGRE_F_L2MISS)) ||
	    nla_put_u8(skb, IFLA_NVGRE_L3MISS,
			!!(nvgre->flags & NVGRE_F_L3MISS)) ||
	    nla_put_u32(skb, IFLA_NVGRE_AGEING, nvgre->age_interval) ||
	    nla_put_u32(skb, IFLA_NVGRE_LIMIT, nvgre->addrmax))
		goto nla_put_failure;


	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops nvgre_link_ops __read_mostly = {
	.kind		= "nvgre",
	.maxtype	= IFLA_NVGRE_MAX,
	.policy		= nvgre_policy,
	.priv_size	= sizeof(struct nvgre_dev),
	.setup		= nvgre_setup,
	.validate	= nvgre_validate,
	.newlink	= nvgre_newlink,
	.dellink	= nvgre_dellink,
	.get_size	= nvgre_get_size,
	.fill_info	= nvgre_fill_info,
};

static const struct gre_protocol nvgre_protocol = {
	.handler = nvgre_rcv,
};

static __net_init int nvgre_init_net(struct net *net)
{
	struct nvgre_net *vn = net_generic(net, nvgre_net_id);
	struct sock *sk;
	int rc;
	unsigned h;

	/* Create UDP socket for encapsulation receive. */
	rc = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &vn->sock);
	if (rc < 0) {
		pr_debug("UDP socket create failed\n");
		return rc;
	}
	/* Put in proper namespace */
	sk = vn->sock->sk;
	sk_change_net(sk, net);


	rc = gre_add_protocol(&nvgre_protocol, GREPROTO_NV);
	if (rc) {
		pr_err("NVGRE: can't add gre protocol\n");
		return rc;
	}

	for (h = 0; h < VNI_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&vn->vni_list[h]);

	return 0;
}

static __net_exit void nvgre_exit_net(struct net *net)
{
	struct nvgre_net *vn = net_generic(net, nvgre_net_id);
	struct nvgre_dev *nvgre;
	unsigned h;

	rtnl_lock();
	for (h = 0; h < VNI_HASH_SIZE; ++h)
		hlist_for_each_entry(nvgre, &vn->vni_list[h], hlist)
			dev_close(nvgre->dev);
	rtnl_unlock();

	gre_del_protocol(&nvgre_protocol, GREPROTO_NV);

	if (vn->sock) {
		sk_release_kernel(vn->sock->sk);
		vn->sock = NULL;
	}
}

static struct pernet_operations nvgre_net_ops = {
	.init = nvgre_init_net,
	.exit = nvgre_exit_net,
	.id   = &nvgre_net_id,
	.size = sizeof(struct nvgre_net),
};

static int __init nvgre_init_module(void)
{
	int rc;

	get_random_bytes(&nvgre_salt, sizeof(nvgre_salt));

	rc = register_pernet_device(&nvgre_net_ops);
	if (rc)
		goto out1;

	rc = rtnl_link_register(&nvgre_link_ops);
	if (rc)
		goto out2;

	return 0;

out2:
	unregister_pernet_device(&nvgre_net_ops);
out1:
	return rc;
}
module_init(nvgre_init_module);

static void __exit nvgre_cleanup_module(void)
{
	rtnl_link_unregister(&nvgre_link_ops);
	unregister_pernet_device(&nvgre_net_ops);
	rcu_barrier();
}
module_exit(nvgre_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_VERSION(NVGRE_VERSION);
MODULE_AUTHOR("Alexandru Copot <alex.mihai.c@gmail.com>");
MODULE_ALIAS_RTNL_LINK("nvgre");
