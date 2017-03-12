#include <net/afnetns.h>
#include <net/net_namespace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>

const struct proc_ns_operations afnetns_operations;

struct afnetns init_afnetns = {
	.ref = REFCOUNT_INIT(1),
};

static struct afnetns *ns_to_afnet(struct ns_common *ns)
{
	return container_of(ns, struct afnetns, ns);
}

static int afnet_setup(struct afnetns *afnetns, struct net *net)
{
	int err;

	afnetns->ns.ops = &afnetns_operations;
	err = ns_alloc_inum(&afnetns->ns);
	if (err)
		return err;

	refcount_set(&afnetns->ref, 1);
	afnetns->net = get_net(net);

	return err;
}

struct afnetns *afnetns_new(struct net *net)
{
	int err;
	struct afnetns *afnetns;

	afnetns = kzalloc(sizeof(*afnetns), GFP_KERNEL);
	if (!afnetns)
		return ERR_PTR(-ENOMEM);

	err = afnet_setup(afnetns, net);
	if (err) {
		kfree(afnetns);
		return ERR_PTR(err);
	}

	return afnetns;
}

void afnetns_free(struct afnetns *afnetns)
{
	ns_free_inum(&afnetns->ns);
	put_net(afnetns->net);
	kfree(afnetns);
}

struct afnetns *copy_afnet_ns(unsigned long flags, struct nsproxy *old)
{
	if (flags & CLONE_NEWNET)
		return afnetns_get(old->net_ns->afnet_ns);

	if (!(flags & CLONE_NEWAFNET))
		return afnetns_get(old->afnet_ns);

	return afnetns_new(old->net_ns);
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

const struct proc_ns_operations afnetns_operations = {
	.name		= "afnet",
	.type		= CLONE_NEWAFNET,
	.get		= afnet_get,
	.put		= afnet_put,
	.install	= afnet_install,
};

int __init afnet_ns_init(void)
{
	int err;

	err = afnet_setup(&init_afnetns, &init_net);
	if (err)
		return err;

	pr_info("afnetns: address family namespaces available\n");
	return err;
}
