/*
 * Author: Yuqiong Sun <suny@us.ibm.com>
*/

#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include "ima.h"

static struct kmem_cache *ns_status_cachep;

/*
static DEFINE_RWLOCK(ns_status_lock);
*/

struct ns_status *ima_get_ns_status(struct ima_namespace *ns, struct integrity_iint_cache *iint)
{
	struct ns_status *status;
	
	list_for_each_entry_rcu(status, &iint->ns_list, ns_next){
		if (status->ns == ns)
		{
			rcu_read_unlock();
			return status;
		}
	}

	/* First time a namespace opened a inode */

	
	status = kmem_cache_alloc(ns_status_cachep, GFP_NOFS);
	if (!status)
		return NULL;
	status->ns = ns;
	status->flags = 0UL;
	INIT_LIST_HEAD(&status->ns_next);
	list_add_tail_rcu(&status->ns_next, &iint->ns_list);
	INIT_LIST_HEAD(&status->iint_next);
	list_add_tail_rcu(&status->iint_next, &ns->iint_list);
	
	return status; 
}

void ima_free_ns_status(struct ima_namespace *ns)
{
	struct ns_status *current_status;
	struct ns_status *next_status;
	
	list_for_each_entry_safe(current_status, next_status, &ns->iint_list, iint_next){
		list_del_rcu(&current_status->ns_next);
		list_del_rcu(&current_status->iint_next);
		current_status->ns = NULL;
		current_status->flags = 0UL;
		kmem_cache_free(ns_status_cachep, current_status);	
	}
}

int ima_ns_status_init(void)
{
        ns_status_cachep = KMEM_CACHE(ns_status, SLAB_PANIC);
	return 0;
}
