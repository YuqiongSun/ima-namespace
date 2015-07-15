/*
* Author: Yuqiong Sun <suny@us.ibm.com>
*/

#include <linux/export.h>
#include <linux/ima_namespace.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/rculist.h>

extern struct list_head ima_default_rules;

struct ima_namespace init_ima_ns = {
	.kref = {
		/* copied from uts, but why?*/
		.refcount = ATOMIC_INIT(2),
	},
	.user_ns = &init_user_ns,
	.ns.inum = PROC_IMA_INIT_INFO,
	.parent = NULL,
	.ima_measurements = LIST_HEAD_INIT(init_ima_ns.ima_measurements),
	.ima_rules = &ima_default_rules,
	.ima_policy_rules = LIST_HEAD_INIT(init_ima_ns.ima_policy_rules),
	.nr_extents = 0,
	.ima_fs_flags = 0,
};
EXPORT_SYMBOL(init_ima_ns);


static struct ima_namespace *create_ima_ns(void)
{
        struct ima_namespace *ima_ns;

        ima_ns = kmalloc(sizeof(struct ima_namespace), GFP_KERNEL);
        if (ima_ns)
                kref_init(&ima_ns->kref);
        return ima_ns;
}

static struct ima_namespace *clone_ima_ns(struct user_namespace *user_ns,
                                          struct ima_namespace *old_ns)
{
        struct ima_namespace *ns;
        int err;

        ns = create_ima_ns();
        if (!ns)
                return ERR_PTR(-ENOMEM);

        err = ns_alloc_inum(&ns->ns);
        if (err) {
                kfree(ns);
                return ERR_PTR(err);
        }

        ns->ns.ops = &imans_operations;
	get_ima_ns(old_ns);
	ns->parent = old_ns;
        ns->user_ns = get_user_ns(user_ns);
	INIT_LIST_HEAD(&ns->ima_measurements);       
	INIT_LIST_HEAD(&ns->ima_policy_rules);
	/*
	* ima_create_policy_file(ns); 
        */
	return ns;
}

struct ima_namespace *copy_ima(unsigned long flags, 
	struct user_namespace *user_ns, struct ima_namespace *old_ns)
{
        struct ima_namespace *new_ns;

	printk(KERN_DEBUG "SYQ: %s, old_ns exists: %d\n", __FUNCTION__, old_ns != NULL);

        BUG_ON(!old_ns);
        get_ima_ns(old_ns);

        if (!(flags & CLONE_NEWIMA))
                return old_ns;

        new_ns = clone_ima_ns(user_ns, old_ns);

        put_ima_ns(old_ns);
        return new_ns;
}

void free_ima_ns(struct kref *kref)
{
        struct ima_namespace *ns;

        ns = container_of(kref, struct ima_namespace, kref);
        put_user_ns(ns->user_ns);
        ns_free_inum(&ns->ns);
        /*
	* Free all the allocated data structures for integrity
	*/
	printk(KERN_DEBUG "SYQ: %s, freeing ima queue entries\n", __FUNCTION__);
	ima_delete_rules(&ns->ima_policy_rules);
	ima_free_queue_entries(ns);
	kfree(ns);
}

static inline struct ima_namespace *to_ima_ns(struct ns_common *ns)
{
        return container_of(ns, struct ima_namespace, ns);
}

static struct ns_common *imans_get(struct task_struct *task)
{
        struct ima_namespace *ns = NULL;
        struct nsproxy *nsproxy;

        task_lock(task);
        nsproxy = task->nsproxy;
        if (nsproxy) {
                ns = nsproxy->ima_ns;
                get_ima_ns(ns);
        }
        task_unlock(task);

        return ns ? &ns->ns : NULL;
}

static void imans_put(struct ns_common *ns)
{
        put_ima_ns(to_ima_ns(ns));
}

static int imans_install(struct nsproxy *nsproxy, struct ns_common *new)
{
        struct ima_namespace *ns = to_ima_ns(new);

        if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
            !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
                return -EPERM;

        get_ima_ns(ns);
        put_ima_ns(nsproxy->ima_ns);
        nsproxy->ima_ns = ns;
        return 0;
}

const struct proc_ns_operations imans_operations = {
        .name           = "ima",
        .type           = CLONE_NEWIMA,
        .get            = imans_get,
        .put            = imans_put,
        .install        = imans_install,
};
