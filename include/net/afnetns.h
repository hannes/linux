#pragma once

#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>

struct afnetns {
#if IS_ENABLED(CONFIG_AFNETNS)
	refcount_t ref;
	struct ns_common ns;
	struct net *net;
#endif
};

extern struct afnetns init_afnetns;

int afnet_ns_init(void);

struct afnetns *afnetns_new(struct net *net);
struct afnetns *copy_afnet_ns(unsigned long flags, struct nsproxy *old);
struct afnetns *afnetns_get_by_fd(int fd);
unsigned int afnetns_to_inode(struct afnetns *afnetns);
void afnetns_free(struct afnetns *afnetns);

static inline struct afnetns *afnetns_get(struct afnetns *afnetns)
{
#if IS_ENABLED(CONFIG_AFNETNS)
	refcount_inc(&afnetns->ref);
#else
	BUILD_BUG();
#endif
	return afnetns;
}

static inline void afnetns_put(struct afnetns *afnetns)
{
#if IS_ENABLED(CONFIG_AFNETNS)
	if (refcount_dec_and_test(&afnetns->ref))
		afnetns_free(afnetns);
#else
	BUILD_BUG();
#endif
}
