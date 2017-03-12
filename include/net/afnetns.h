/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NET_AFNETNS_H__
#define __NET_AFNETNS_H__

#include <linux/refcount.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>

#ifdef CONFIG_AFNETNS

struct afnetns {
	struct user_namespace *user_ns;
	struct net *net;
	bool owned;
	refcount_t ref;
	struct ucounts *ucounts;
	struct ns_common ns;
};

extern struct afnetns init_afnet;

int afnet_ns_init(void);
struct afnetns *afnetns_new(struct net *net, struct user_namespace *user_ns,
			    bool owned);
struct afnetns *copy_afnet_ns(unsigned long flags,
			      struct user_namespace *user_ns,
			      struct nsproxy *old);
struct afnetns *afnetns_get_by_fd(int fd);
unsigned int afnetns_to_inode(struct afnetns *afnetns);
void afnetns_destruct_owned(struct afnetns *afnetns);
void afnetns_destruct(struct afnetns *afnetns);

static inline struct afnetns *afnetns_get(struct afnetns *afnetns)
{
	if (afnetns->owned)
		get_net(afnetns->net);
	else
		refcount_inc(&afnetns->ref);
	return afnetns;
}

static inline void afnetns_put(struct afnetns *afnetns)
{
	if (afnetns->owned) {
		put_net(afnetns->net);
	} else {
		if (refcount_dec_and_test(&afnetns->ref))
			afnetns_destruct(afnetns);
	}
}

static inline struct afnetns *afnetns_get_current(void)
{
	return afnetns_get(current->nsproxy->afnet_ns);
}

#else /* CONFIG_AFNETNS */

struct afnetns;

#endif /* CONFIG_AFNETNS */

#endif /* __NET_AFNETNS_H__ */
