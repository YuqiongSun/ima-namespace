/*
* Author: Yuqiong Sun <suny@us.ibm.com>
*/

#include <linux/kref.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/rculist.h>
#include <linux/sched.h>

/* Moved from ima.h to ima_namespace.h */
#ifndef IMA_HASH_BITS
#define IMA_HASH_BITS 9
#endif
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)

struct ima_h_table{
	atomic_long_t len;	/* number of stored measurements in the list */
	atomic_long_t violations;
	struct hlist_head queue[IMA_MEASURE_HTABLE_SIZE];
};

enum ima_fs_flags {
        IMA_FS_BUSY,
};

struct ima_namespace{
	struct kref kref;
	struct user_namespace *user_ns;
	struct ns_common ns;
	struct ima_namespace *parent;
	struct list_head ima_measurements;
	struct list_head *ima_rules;
	struct list_head ima_policy_rules;
	struct list_head iint_list;
	int nr_extents;
	unsigned long ima_fs_flags;	/* ima_policy file avaiability*/
	int ima_policy_flag;		/* for policy quick check */
	struct ima_h_table ima_htable;
};

extern struct ima_namespace init_ima_ns;

extern void ima_free_queue_entries(struct ima_namespace *ns);
extern void ima_delete_rules(struct list_head *ima_policy_rules);

extern struct ima_namespace *copy_ima(unsigned long flags,
	struct user_namespace *user_ns, struct ima_namespace *old_ns);

extern void free_ima_ns(struct kref *kref);

extern int ima_open_policy(struct inode *inode, struct file *filp, struct ima_namespace *ns);

extern ssize_t ima_write_policy(struct file *file, const char __user *buf, 
				size_t size, loff_t *ppos, struct ima_namespace *ns);

extern int ima_release_policy(struct inode *inode, struct file *file, struct ima_namespace *ns);

extern void ima_update_policy_flag(struct ima_namespace *ns);
extern void ima_free_ns_status(struct ima_namespace *ns);

static inline void get_ima_ns(struct ima_namespace *ns)
{
	kref_get(&ns->kref);
}


static inline void put_ima_ns(struct ima_namespace *ns)
{
	kref_put(&ns->kref, free_ima_ns);
}

static inline struct ima_namespace *get_current_ns(void)
{
	return current->nsproxy->ima_ns;
}

static inline struct list_head *get_measurements(void)
{
	return &current->nsproxy->ima_ns->ima_measurements;
}

static inline struct list_head **get_current_ima_rules(void)
{
	return &current->nsproxy->ima_ns->ima_rules;
}

static inline struct list_head **get_ima_rules(struct ima_namespace *ns)
{
	return &ns->ima_rules;
}

static inline struct list_head *get_ima_policy_rules(struct ima_namespace *ns)
{
	return &ns->ima_policy_rules;
}

static inline struct list_head *get_current_ima_policy_rules(void)
{
	return &current->nsproxy->ima_ns->ima_policy_rules;
}
