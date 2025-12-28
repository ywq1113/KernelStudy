# Fair

## CFS



## Features

**Next Buddy**

开启 next buddy feature 后，会优先调度刚刚唤醒的 task。对延迟有影响但长期来讲并不会影响公平性。

```c
/*
 * Pick the next process, keeping these things in mind, in this order:
 * 1) keep things fair between processes/task groups
 * 2) pick the "next" process, since someone really wants that to run
 * 3) pick the "last" process, for cache locality
 * 4) do not run the "skip" process, if something else is available
 */
static struct sched_entity *
pick_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	/*
	 * Enabling NEXT_BUDDY will affect latency but not fairness.
	 */
	if (sched_feat(NEXT_BUDDY) &&
	    cfs_rq->next && entity_eligible(cfs_rq, cfs_rq->next))
		return cfs_rq->next;

	return pick_eevdf(cfs_rq);
}
```