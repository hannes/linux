#include <net/afnetns.h>
#include <net/net_namespace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/file.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
#include <linux/user_namespace.h>

const struct proc_ns_operations afnetns_operations;

struct afnetns init_afnetns = {
	.ref = REFCOUNT_INIT(1),
};

static struct afnetns *ns_to_afnet(struct ns_common *ns)
{
	return container_of(ns, struct afnetns, ns);
}

static int afnet_setup(struct afnetns *afnetns, struct net *net,
		       struct user_namespace *user_ns)
{
	int err;

	afnetns->ns.ops = &afnetns_operations;
	err = ns_alloc_inum(&afnetns->ns);
	if (err)
		return err;

	refcount_set(&afnetns->ref, 1);
	afnetns->net = get_net(net);
	afnetns->user_ns = get_user_ns(user_ns);

	return err;
}

struct afnetns *afnetns_new(struct net *net, struct user_namespace *user_ns)
{
	int err;
	struct afnetns *afnetns;

	afnetns = kzalloc(sizeof(*afnetns), GFP_KERNEL);
	if (!afnetns)
		return ERR_PTR(-ENOMEM);

	err = afnet_setup(afnetns, net, user_ns);
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
	put_user_ns(afnetns->user_ns);
	kfree(afnetns);
}
EXPORT_SYMBOL(afnetns_free);

struct afnetns *afnetns_get_by_fd(int fd)
{
	struct file *file;
	struct ns_common *ns;
	struct afnetns *afnetns;

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

	return afnetns_new(old->net_ns, user_ns);
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

	err = afnet_setup(&init_afnetns, &init_net, &init_user_ns);
	if (err)
		return err;

	pr_info("afnetns: address family namespaces available\n");
	return err;
}
