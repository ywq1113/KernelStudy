# Core

## entry schedule

```c
asmlinkage __visible void __sched schedule(void)
{
	struct task_struct *tsk = current;

	sched_submit_work(tsk);  // 在真正切走 CPU 之前，把该处理的“工作提交”出去，避免带着脏状态去睡/切换
	do {
		preempt_disable();  // 进入“不可抢占区”，保证切换过程原子性
		__schedule(SM_NONE);
		sched_preempt_enable_no_resched();  // 避免刚调度完立刻又调度
	} while (need_resched());
	sched_update_worker(tsk);
}

static __always_inline bool need_resched(void)
{
	return unlikely(tif_need_resched());
}

static __always_inline bool tif_need_resched(void)  // 定时器中断、wakeup、抢占逻辑等会修改 flag 为 TIF_NEED_RESCHED
{
	return test_bit(TIF_NEED_RESCHED,
			(unsigned long *)(&current_thread_info()->flags));
}

static inline void sched_submit_work(struct task_struct *tsk)
{
	unsigned int task_flags;

	if (task_is_running(tsk))
		return;

	task_flags = tsk->flags;
	/*
	 * If a worker goes to sleep, notify and ask workqueue whether it
	 * wants to wake up a task to maintain concurrency.
	 */
	if (task_flags & (PF_WQ_WORKER | PF_IO_WORKER)) {
		if (task_flags & PF_WQ_WORKER)
			wq_worker_sleeping(tsk);
		else
			io_wq_worker_sleeping(tsk);
	}

	/*
	 * spinlock and rwlock must not flush block requests.  This will
	 * deadlock if the callback attempts to acquire a lock which is
	 * already acquired.
	 */
	SCHED_WARN_ON(current->__state & TASK_RTLOCK_WAIT);

	/*
	 * If we are going to sleep and we have plugged IO queued,
	 * make sure to submit it to avoid deadlocks.
	 */
	blk_flush_plug(tsk->plug, true);
}
```

Note：preempt_disable 是内核抢占（preemption），不是中断。中断是否能打断取决于 IRQ 状态。

```c
// preempt.h
#define preempt_disable() \
do { \
	preempt_count_inc(); \
	barrier(); \
} while (0)

#define sched_preempt_enable_no_resched() \
do { \
	barrier(); \
	preempt_count_dec(); \
} while (0)
```

schedule 最核心函数，在严格的并发/内存序/状态约束下，把 per cpu 运行队列中的 prev task 安全地换成 next task。
- 调度是 per cpu 的

- rq_lock 的部分是解决 lost wakeup 的一种竞态

  任务准备睡眠（TASK_INTERRUPTIBLE）并进入 schedule()，与此同时另一个 CPU 发信号并试图唤醒它（signal_wake_up()）。如果内存操作发生乱序，就可能出现：
    - 信号已经来了，但唤醒方“看不到你已经进入可被唤醒的睡眠态”，于是它不唤醒；
    - 你这边随后真的睡下去，于是就可能“睡过头”（直到下次别的事件再唤醒）
  内核用 rq_lock() + smp_mb__after_spinlock() 来把关键读写顺序钉死，避免这种丢唤醒。

```c
static void __sched notrace __schedule(unsigned int sched_mode)
{
	struct task_struct *prev, *next;
	unsigned long *switch_count;
	unsigned long prev_state;
	struct rq_flags rf;
	struct rq *rq;
	int cpu;

	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	prev = rq->curr;

    // 1. 检查 task 内核栈末尾的 guard，不能发生栈溢出、越界写、野指针等操作 task_stack_end_corrupted(prev)
    // 2. 避免 ROP、return address 覆盖 task_scs_end_corrupted(prev)
    // 3. 避免在 atomic / non-blocking 区域里调用了会睡眠的路径
	schedule_debug(prev, !!sched_mode);

    // 1. timer 触发方式：hard irq -> soft irq
	if (sched_feat(HRTICK) || sched_feat(HRTICK_DL))
		hrtick_clear(rq);

	local_irq_disable();  // 关本地中断：防止 IRQ 打断调度关键路径
	rcu_note_context_switch(!!sched_mode);  // 告诉 RCU：要做 context switch 了

	/*
	 * Make sure that signal_pending_state()->signal_pending() below
	 * can't be reordered with __set_current_state(TASK_INTERRUPTIBLE)
	 * done by the caller to avoid the race with signal_wake_up():
	 *
	 * __set_current_state(@state)		signal_wake_up()
	 * schedule()				  set_tsk_thread_flag(p, TIF_SIGPENDING)
	 *					  wake_up_state(p, state)
	 *   LOCK rq->lock			    LOCK p->pi_state
	 *   smp_mb__after_spinlock()		    smp_mb__after_spinlock()
	 *     if (signal_pending_state())	    if (p->state & @state)
	 *
	 * Also, the membarrier system call requires a full memory barrier
	 * after coming from user-space, before storing to rq->curr.
	 */
	rq_lock(rq, &rf);
	smp_mb__after_spinlock();

	/* Promote REQ to ACT */
	rq->clock_update_flags <<= 1;
	update_rq_clock(rq);

	switch_count = &prev->nivcsw;

	/*
	 * We must load prev->state once (task_struct::state is volatile), such
	 * that we form a control dependency vs deactivate_task() below.
	 */
	prev_state = READ_ONCE(prev->__state);
	if (!(sched_mode & SM_MASK_PREEMPT) && prev_state) {
		if (signal_pending_state(prev_state, prev)) {
			WRITE_ONCE(prev->__state, TASK_RUNNING);
		} else {
			prev->sched_contributes_to_load =
				(prev_state & TASK_UNINTERRUPTIBLE) &&
				!(prev_state & TASK_NOLOAD) &&
				!(prev_state & TASK_FROZEN);

			if (prev->sched_contributes_to_load)
				rq->nr_uninterruptible++;

			/*
			 * __schedule()			ttwu()
			 *   prev_state = prev->state;    if (p->on_rq && ...)
			 *   if (prev_state)		    goto out;
			 *     p->on_rq = 0;		  smp_acquire__after_ctrl_dep();
			 *				  p->state = TASK_WAKING
			 *
			 * Where __schedule() and ttwu() have matching control dependencies.
			 *
			 * After this, schedule() must not care about p->state any more.
			 */
			deactivate_task(rq, prev, DEQUEUE_SLEEP | DEQUEUE_NOCLOCK);

			if (prev->in_iowait) {
				atomic_inc(&rq->nr_iowait);
				delayacct_blkio_start();
			}
		}
		switch_count = &prev->nvcsw;
	}

	next = pick_next_task(rq, prev, &rf);
	clear_tsk_need_resched(prev);
	clear_preempt_need_resched();
#ifdef CONFIG_SCHED_DEBUG
	rq->last_seen_need_resched_ns = 0;
#endif

	if (likely(prev != next)) {
		rq->nr_switches++;
		/*
		 * RCU users of rcu_dereference(rq->curr) may not see
		 * changes to task_struct made by pick_next_task().
		 */
		RCU_INIT_POINTER(rq->curr, next);
		/*
		 * The membarrier system call requires each architecture
		 * to have a full memory barrier after updating
		 * rq->curr, before returning to user-space.
		 *
		 * Here are the schemes providing that barrier on the
		 * various architectures:
		 * - mm ? switch_mm() : mmdrop() for x86, s390, sparc, PowerPC.
		 *   switch_mm() rely on membarrier_arch_switch_mm() on PowerPC.
		 * - finish_lock_switch() for weakly-ordered
		 *   architectures where spin_unlock is a full barrier,
		 * - switch_to() for arm64 (weakly-ordered, spin_unlock
		 *   is a RELEASE barrier),
		 */
		++*switch_count;

		migrate_disable_switch(rq, prev);
		psi_sched_switch(prev, next, !task_on_rq_queued(prev));

		trace_sched_switch(sched_mode & SM_MASK_PREEMPT, prev, next, prev_state);

		/* Also unlocks the rq: */
		rq = context_switch(rq, prev, next, &rf);
	} else {
		rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);

		rq_unpin_lock(rq, &rf);
		__balance_callbacks(rq);
		raw_spin_rq_unlock_irq(rq);
	}
}
```