/*
* Author: Yuqiong Sun <suny@us.ibm.com>
*/

#include <linux/export.h>
#include <linux/ima_namespace.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>
#include <linux/random.h>
#include <linux/key.h>
#include <linux/key-type.h>

extern struct list_head ima_default_rules;

struct ima_namespace init_ima_ns = {
	.kref = {
		/* copied from uts, but why?*/
		.refcount = ATOMIC_INIT(2),
	},
	.user_ns = &init_user_ns,
	.ns.inum = PROC_IMA_INIT_INFO,
	.ns.ops = &imans_operations,
	.parent = NULL,
	.ima_measurements = LIST_HEAD_INIT(init_ima_ns.ima_measurements),
	.ima_rules = &ima_default_rules,
	.ima_policy_rules = LIST_HEAD_INIT(init_ima_ns.ima_policy_rules),
	.iint_list = LIST_HEAD_INIT(init_ima_ns.iint_list),
	.nr_extents = 0,
#ifndef CONFIG_IMA_TRUSTED_KEYRING
	.ima_keyring = "_ima",
#else
	.ima_keyring = ".ima",
#endif
	.ima_fs_flags = 0,
	.ima_policy_flag = 0,
	.ima_htable = {
		.len = ATOMIC_LONG_INIT(0),
		.violations = ATOMIC_LONG_INIT(0),
		.queue[0 ... IMA_MEASURE_HTABLE_SIZE - 1] = HLIST_HEAD_INIT,
	},
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
	int i;
	int random;
	key_ref_t keyring_ref, ima_keyring_ref;
	//key_ref_t ima_keyring_parent_ref;
	struct key *key;
	//char parent_keyring[IMA_KEYRING_NAME_SIZE + 2];

	const struct cred *cred = current_cred();

        ns = create_ima_ns();
        if (!ns)
                return ERR_PTR(-ENOMEM);

        err = ns_alloc_inum(&ns->ns);
        if (err) goto error;

	get_random_bytes(&random, sizeof(random));
	memset(ns->ima_keyring, '\0', IMA_KEYRING_NAME_SIZE);
	sprintf(ns->ima_keyring, "%s_%08x", init_ima_ns.ima_keyring, random);

	/* Create keyring 
	 * Maybe we should let userspace create the keyring?
	*/
/*
	ima_keyring = keyring_alloc(ns->ima_keyring, cred->uid, 
				cred->gid, cred, 
				(KEY_POS_ALL & ~KEY_POS_SETATTR) 
				| KEY_USR_ALL, KEY_ALLOC_IN_QUOTA, 
				NULL);
*/
	if (!cred->user->uid_keyring) {
		pr_info("SYQ: user keyring doesn't exist\n");
		goto error;
	}

	key = cred->user->uid_keyring;
	__key_get(key);
	keyring_ref = make_key_ref(key, 1);
	if (IS_ERR(keyring_ref)) {
		err = PTR_ERR(keyring_ref);
		pr_info("SYQ: Can't find user keyring\n");
		goto error;
	}

	ima_keyring_ref = key_create_or_update(keyring_ref, "keyring", ns->ima_keyring, 
					   NULL, 0, KEY_PERM_UNDEF, KEY_ALLOC_IN_QUOTA); 
	if (IS_ERR(ima_keyring_ref)) {
		err = PTR_ERR(ima_keyring_ref);
		pr_info("SYQ: Can't allocate %s keyring (%d)\n", ns->ima_keyring, err);
		goto error;
	}

/*
	sprintf(parent_keyring, "%s%s", "p_", ns->ima_keyring);
	ima_keyring_parent_ref = key_create_or_update(keyring_ref, "keyring", parent_keyring,
							NULL, 0, KEY_PERM_UNDEF, KEY_ALLOC_IN_QUOTA);
	
	if (IS_ERR(ima_keyring_parent_ref)) {
		err = PTR_ERR(ima_keyring_parent_ref);
		pr_info("SYQ: Can't allocate %s keyring (%d)\n", parent_keyring, err);
		goto error;
	}
*/
        ns->ns.ops = &imans_operations;
	/* parent ref count increase by 1 */
	get_ima_ns(old_ns);
	ns->parent = old_ns;
        ns->user_ns = get_user_ns(user_ns);
	INIT_LIST_HEAD(&ns->ima_measurements);       
	INIT_LIST_HEAD(&ns->ima_policy_rules);
	INIT_LIST_HEAD(&ns->iint_list);
	ns->ima_rules = &ima_default_rules,
	ns->nr_extents = 0;
	ns->ima_fs_flags = 0;

	atomic_long_set(&ns->ima_htable.len, 0);
	atomic_long_set(&ns->ima_htable.violations, 0);
	//ns->ima_htable.queue[0 ... IMA_MEASURE_HTABLE_SIZE - 1] = HLIST_HEAD_INIT;
	for (i=0; i<IMA_MEASURE_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&ns->ima_htable.queue[i]);
	ima_update_policy_flag(ns);	
	return ns;
error:
	kfree(ns);
	return ERR_PTR(err);
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

static void destroy_ima_ns(struct ima_namespace *ns)
{
	struct key *ima_keyring, *user_keyring;
	const struct cred *cred = current_cred();

        put_user_ns(ns->user_ns);
        ns_free_inum(&ns->ns);
	
	/*
	 * Free all keys
	 * 
	 */
	ima_keyring = request_key(&key_type_keyring, ns->ima_keyring, NULL);	
	if (ima_keyring)
		keyring_clear(ima_keyring);
	user_keyring = cred->user->uid_keyring;
	if (user_keyring) {
		key_unlink(user_keyring, ima_keyring);
		key_put(user_keyring);
	}
        /*
	* Free all the allocated data structures for integrity
	*/
	printk(KERN_DEBUG "SYQ: %s, freeing ima queue entries\n", __FUNCTION__);
	ima_delete_rules(&ns->ima_policy_rules);
	ima_free_queue_entries(ns);
	ima_free_ns_status(ns);
	kfree(ns);
}

void free_ima_ns(struct kref *kref)
{
        struct ima_namespace *ns;
	struct ima_namespace *parent;

        ns = container_of(kref, struct ima_namespace, kref);
	while (ns != &init_ima_ns)
	{
		parent = ns->parent;
		destroy_ima_ns(ns);
		put_ima_ns(parent);
		ns = parent;
	}
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
