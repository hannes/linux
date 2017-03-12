/* SPDX-License-Identifier: GPL-2.0 */

#include <net/afnetns.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/file.h>
#include <linux/proc_ns.h>

const struct proc_ns_operations afnetns_operations;

struct afnetns init_afnet = {
	.owned = true,
	.ref = REFCOUNT_INIT(1),
};

static struct afnetns *ns_to_afnet(struct ns_common *ns)
{
	return container_of(ns, struct afnetns, ns);
}

static int afnetns_setup(struct afnetns *afnetns, struct net *net,
			 struct user_namespace *user_ns, bool owned)
{
	int err;

	afnetns->ns.ops = &afnetns_operations;
	err = ns_alloc_inum(&afnetns->ns);
	if (err)
		return err;

	afnetns->owned = owned;
	refcount_set(&afnetns->ref, 1);
	afnetns->net = owned ? net : get_net(net);
	afnetns->user_ns = get_user_ns(user_ns);

	return err;
}

static struct kmem_cache *afnet_cache;

struct afnetns *afnetns_new(struct net *net, struct user_namespace *user_ns,
			    bool owned)
{
	struct ucounts *ucounts = NULL;
	struct afnetns *afnetns;
	int err;

	if (!owned) {
		ucounts = inc_ucount(user_ns, current_euid(),
				     UCOUNT_AFNET_NAMESPACES);
		if (!ucounts)
			return ERR_PTR(-ENOSPC);
	}

	afnetns = kmem_cache_zalloc(afnet_cache, GFP_KERNEL);
	if (!afnetns) {
		if (ucounts)
			dec_ucount(ucounts, UCOUNT_AFNET_NAMESPACES);
		return ERR_PTR(-ENOMEM);
	}

	err = afnetns_setup(afnetns, net, user_ns, owned);
	if (err) {
		kmem_cache_free(afnet_cache, afnetns);
		if (ucounts)
			dec_ucount(ucounts, UCOUNT_AFNET_NAMESPACES);
		return ERR_PTR(err);
	}

	if (ucounts)
		afnetns->ucounts = ucounts;

	return afnetns;
}

void afnetns_destruct(struct afnetns *afnetns)
{
	struct ucounts *ucounts = afnetns->ucounts;

	ns_free_inum(&afnetns->ns);
	put_net(afnetns->net);
	put_user_ns(afnetns->user_ns);
	kmem_cache_free(afnet_cache, afnetns);
	dec_ucount(ucounts, UCOUNT_AFNET_NAMESPACES);
}
EXPORT_SYMBOL(afnetns_destruct);

void afnetns_destruct_owned(struct afnetns *afnetns)
{
	WARN_ON_ONCE(!afnetns->owned);
	WARN_ON_ONCE(refcount_read(&afnetns->ref) != 1);

	ns_free_inum(&afnetns->ns);
	put_user_ns(afnetns->user_ns);
	kmem_cache_free(afnet_cache, afnetns);
}

struct afnetns *afnetns_get_by_fd(int fd)
{
	struct afnetns *afnetns;
	struct ns_common *ns;
	struct file *file;

	file = proc_ns_fget(fd);
	if (IS_ERR(file))
		return ERR_CAST(file);

	ns = get_proc_ns(file_inode(file));
	if (ns->ops == &afnetns_operations)
		afnetns = afnetns_get(ns_to_afnet(ns));
	else
		afnetns = ERR_PTR(-EINVAL);

	fput(file);
	return afnetns;
}
EXPORT_SYMBOL(afnetns_get_by_fd);

unsigned int afnetns_to_inode(struct afnetns *afnetns)
{
	return afnetns->ns.inum;
}
EXPORT_SYMBOL(afnetns_to_inode);

struct afnetns *copy_afnet_ns(unsigned long flags,
			      struct user_namespace *user_ns,
			      struct nsproxy *old)
{
	if (flags & CLONE_NEWNET)
		return afnetns_get(old->net_ns->afnet_ns);

	if (!(flags & CLONE_NEWAFNET))
		return afnetns_get(old->afnet_ns);

	return afnetns_new(old->net_ns, user_ns, false);
}

static struct ns_common *afnet_get(struct task_struct *task)
{
	struct afnetns *afnetns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy)
		afnetns = afnetns_get(nsproxy->afnet_ns);
	task_unlock(task);
	return afnetns ? &afnetns->ns : NULL;
}

static void afnet_put(struct ns_common *ns)
{
	afnetns_put(ns_to_afnet(ns));
}

static int afnet_install(struct nsproxy *nsproxy, struct ns_common *ns)
{
	struct afnetns *afnetns = ns_to_afnet(ns);

	if (!ns_capable(afnetns->net->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	/* don't allow cross netns setns */
	if (!net_eq(nsproxy->net_ns, afnetns->net))
		return -EINVAL;

	afnetns_put(nsproxy->afnet_ns);
	nsproxy->afnet_ns = afnetns_get(afnetns);

	return 0;
}

static struct user_namespace *afnet_owner(struct ns_common *ns)
{
	return ns_to_afnet(ns)->user_ns;
}

const struct proc_ns_operations afnetns_operations = {
	.name		= "afnet",
	.type		= CLONE_NEWAFNET,
	.get		= afnet_get,
	.put		= afnet_put,
	.install	= afnet_install,
	.owner		= afnet_owner,
};

int __init afnet_ns_init(void)
{
	int err;

	afnet_cache = kmem_cache_create("afnet_namespace",
					sizeof(struct afnetns), SMP_CACHE_BYTES,
					SLAB_PANIC, NULL);

	err = afnetns_setup(&init_afnet, &init_net, &init_user_ns, true);
	if (err)
		return err;

	pr_info("afnetns: address family namespaces available\n");
	return err;
}
