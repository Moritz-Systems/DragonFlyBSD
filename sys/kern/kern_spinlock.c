/*
 * Copyright (c) 2005 Jeffrey M. Hsu.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Jeffrey M. Hsu. and Matthew Dillon
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The implementation is designed to avoid looping when compatible operations
 * are executed.
 *
 * To acquire a spinlock we first increment counta.  Then we check if counta
 * meets our requirements.  For an exclusive spinlock it must be 1, of a
 * shared spinlock it must either be 1 or the SHARED_SPINLOCK bit must be set.
 *
 * Shared spinlock failure case: Decrement the count, loop until we can
 * transition from 0 to SHARED_SPINLOCK|1, or until we find SHARED_SPINLOCK
 * is set and increment the count.
 *
 * Exclusive spinlock failure case: While maintaining the count, clear the
 * SHARED_SPINLOCK flag unconditionally.  Then use an atomic add to transfer
 * the count from the low bits to the high bits of counta.  Then loop until
 * all low bits are 0.  Once the low bits drop to 0 we can transfer the
 * count back with an atomic_cmpset_int(), atomically, and return.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#ifdef INVARIANTS
#include <sys/proc.h>
#endif
#include <sys/priv.h>
#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <machine/clock.h>
#include <sys/indefinite2.h>
#include <sys/spinlock.h>
#include <sys/spinlock2.h>
#include <sys/ktr.h>

#ifdef _KERNEL_VIRTUAL
#include <pthread.h>
#endif

struct spinlock pmap_spin = SPINLOCK_INITIALIZER(pmap_spin, "pmap_spin");

/*
 * Kernal Trace
 */
#if !defined(KTR_SPIN_CONTENTION)
#define KTR_SPIN_CONTENTION	KTR_ALL
#endif
#define SPIN_STRING	"spin=%p type=%c"
#define SPIN_ARG_SIZE	(sizeof(void *) + sizeof(int))

KTR_INFO_MASTER(spin);
#if 0
KTR_INFO(KTR_SPIN_CONTENTION, spin, beg, 0, SPIN_STRING, SPIN_ARG_SIZE);
KTR_INFO(KTR_SPIN_CONTENTION, spin, end, 1, SPIN_STRING, SPIN_ARG_SIZE);
#endif

#define logspin(name, spin, type)			\
	KTR_LOG(spin_ ## name, spin, type)

#ifdef INVARIANTS
static int spin_lock_test_mode;
#endif

#ifdef DEBUG_LOCKS_LATENCY

static long spinlocks_add_latency;
SYSCTL_LONG(_debug, OID_AUTO, spinlocks_add_latency, CTLFLAG_RW,
    &spinlocks_add_latency, 0,
    "Add spinlock latency");

#endif

/*
 * We contested due to another exclusive lock holder.  We lose.
 *
 * We have to unwind the attempt and may acquire the spinlock
 * anyway while doing so.
 */
int
spin_trylock_contested(struct spinlock *spin)
{
	globaldata_t gd = mycpu;

	/*
	 * Handle degenerate case, else fail.
	 */
	if (atomic_cmpset_int(&spin->counta, SPINLOCK_SHARED|0, 1))
		return TRUE;
	/*atomic_add_int(&spin->counta, -1);*/
	--gd->gd_spinlocks;
	crit_exit_raw(gd->gd_curthread);

	return (FALSE);
}

/*
 * The spin_lock() inline was unable to acquire the lock and calls this
 * function with spin->counta already incremented, passing (spin->counta - 1)
 * to the function (the result of the inline's fetchadd).
 *
 * atomic_swap_int() is the absolute fastest spinlock instruction, at
 * least on multi-socket systems.  All instructions seem to be about
 * the same on single-socket multi-core systems.  However, atomic_swap_int()
 * does not result in an even distribution of successful acquisitions.
 *
 * UNFORTUNATELY we cannot really use atomic_swap_int() when also implementing
 * shared spin locks, so as we do a better job removing contention we've
 * moved to atomic_cmpset_int() to be able handle multiple states.
 *
 * Another problem we have is that (at least on the 48-core opteron we test
 * with) having all 48 cores contesting the same spin lock reduces
 * performance to around 600,000 ops/sec, verses millions when fewer cores
 * are going after the same lock.
 *
 * Backoff algorithms can create even worse starvation problems, and don't
 * really improve performance when a lot of cores are contending.
 *
 * Our solution is to allow the data cache to lazy-update by reading it
 * non-atomically and only attempting to acquire the lock if the lazy read
 * looks good.  This effectively limits cache bus bandwidth.  A cpu_pause()
 * (for intel/amd anyhow) is not strictly needed as cache bus resource use
 * is governed by the lazy update.
 *
 * WARNING!!!!  Performance matters here, by a huge margin.
 *
 *	48-core test with pre-read / -j 48 no-modules kernel compile
 *	with fanned-out inactive and active queues came in at 55 seconds.
 *
 *	48-core test with pre-read / -j 48 no-modules kernel compile
 *	came in at 75 seconds.  Without pre-read it came in at 170 seconds.
 *
 *	4-core test with pre-read / -j 48 no-modules kernel compile
 *	came in at 83 seconds.  Without pre-read it came in at 83 seconds
 *	as well (no difference).
 */
void
_spin_lock_contested(struct spinlock *spin, const char *ident, int value)
{
	thread_t td = curthread;

	/*
	 * WARNING! Caller has already incremented the lock.  We must
	 *	    increment the count value (from the inline's fetch-add)
	 *	    to match.
	 *
	 * Handle the degenerate case where the spinlock is flagged SHARED
	 * with only our reference.  We can convert it to EXCLUSIVE.
	 */
	++value;
	if (value == (SPINLOCK_SHARED | 1)) {
		if (atomic_cmpset_int(&spin->counta, SPINLOCK_SHARED | 1, 1))
			return;
	}
	indefinite_init(&td->td_indefinite, ident, 0, 'S');

	/*
	 * Transfer our exclusive request to the high bits and clear the
	 * SPINLOCK_SHARED bit if it was set.  This makes the spinlock
	 * appear exclusive, preventing any NEW shared or exclusive
	 * spinlocks from being obtained while we wait for existing
	 * shared or exclusive holders to unlock.
	 *
	 * Don't tread on earlier exclusive waiters by stealing the lock
	 * away early if the low bits happen to now be 1.
	 *
	 * The shared unlock understands that this may occur.
	 */
	atomic_add_int(&spin->counta, SPINLOCK_EXCLWAIT - 1);
	if (value & SPINLOCK_SHARED)
		atomic_clear_int(&spin->counta, SPINLOCK_SHARED);

	/*
	 * Spin until we can acquire a low-count of 1.
	 */
	for (;;) {
		/*
		 * If the low bits are zero, try to acquire the exclusive lock
		 * by transfering our high bit reservation to the low bits.
		 *
		 * NOTE: Reading spin->counta prior to the swap is extremely
		 *	 important on multi-chip/many-core boxes.  On 48-core
		 *	 this one change improves fully concurrent all-cores
		 *	 compiles by 100% or better.
		 *
		 *	 I can't emphasize enough how important the pre-read
		 *	 is in preventing hw cache bus armageddon on
		 *	 multi-chip systems.  And on single-chip/multi-core
		 *	 systems it just doesn't hurt.
		 */
		uint32_t ovalue = spin->counta;
		cpu_ccfence();
		if ((ovalue & (SPINLOCK_EXCLWAIT - 1)) == 0 &&
		    atomic_cmpset_int(&spin->counta, ovalue,
				      (ovalue - SPINLOCK_EXCLWAIT) | 1)) {
			break;
		}
		if (indefinite_check(&td->td_indefinite))
			break;
	}
	indefinite_done(&td->td_indefinite);
}

/*
 * The spin_lock_shared() inline was unable to acquire the lock and calls
 * this function with spin->counta already incremented.
 *
 * This is not in the critical path unless there is contention between
 * shared and exclusive holders.
 */
void
_spin_lock_shared_contested(struct spinlock *spin, const char *ident)
{
	thread_t td = curthread;

	indefinite_init(&td->td_indefinite, ident, 0, 's');

	/*
	 * Undo the inline's increment.
	 */
	atomic_add_int(&spin->counta, -1);

#ifdef DEBUG_LOCKS_LATENCY
	long j;
	for (j = spinlocks_add_latency; j > 0; --j)
		cpu_ccfence();
#endif

	for (;;) {
		/*
		 * Loop until we can acquire the shared spinlock.  Note that
		 * the low bits can be zero while the high EXCLWAIT bits are
		 * non-zero.  In this situation exclusive requesters have
		 * priority (otherwise shared users on multiple cpus can hog
		 * the spinlnock).
		 *
		 * NOTE: Reading spin->counta prior to the swap is extremely
		 *	 important on multi-chip/many-core boxes.  On 48-core
		 *	 this one change improves fully concurrent all-cores
		 *	 compiles by 100% or better.
		 *
		 *	 I can't emphasize enough how important the pre-read
		 *	 is in preventing hw cache bus armageddon on
		 *	 multi-chip systems.  And on single-chip/multi-core
		 *	 systems it just doesn't hurt.
		 */
		uint32_t ovalue = spin->counta;

		cpu_ccfence();
		if (ovalue == 0) {
			if (atomic_cmpset_int(&spin->counta, 0,
					      SPINLOCK_SHARED | 1))
				break;
		} else if (ovalue & SPINLOCK_SHARED) {
			if (atomic_cmpset_int(&spin->counta, ovalue,
					      ovalue + 1))
				break;
		}
		if (indefinite_check(&td->td_indefinite))
			break;
	}
	indefinite_done(&td->td_indefinite);
}

/*
 * If INVARIANTS is enabled various spinlock timing tests can be run
 * by setting debug.spin_lock_test:
 *
 *	1	Test the indefinite wait code
 *	2	Time the best-case exclusive lock overhead (spin_test_count)
 *	3	Time the best-case shared lock overhead (spin_test_count)
 */

#ifdef INVARIANTS

static int spin_test_count = 10000000;
SYSCTL_INT(_debug, OID_AUTO, spin_test_count, CTLFLAG_RW, &spin_test_count, 0,
    "Number of iterations to use for spinlock wait code test");

static int
sysctl_spin_lock_test(SYSCTL_HANDLER_ARGS)
{
        struct spinlock spin;
	int error;
	int value = 0;
	int i;

	if ((error = priv_check(curthread, PRIV_ROOT)) != 0)
		return (error);
	if ((error = SYSCTL_IN(req, &value, sizeof(value))) != 0)
		return (error);

	/*
	 * Indefinite wait test
	 */
	if (value == 1) {
		spin_init(&spin, "sysctllock");
		spin_lock(&spin);	/* force an indefinite wait */
		spin_lock_test_mode = 1;
		spin_lock(&spin);
		spin_unlock(&spin);	/* Clean up the spinlock count */
		spin_unlock(&spin);
		spin_lock_test_mode = 0;
	}

	/*
	 * Time best-case exclusive spinlocks
	 */
	if (value == 2) {
		globaldata_t gd = mycpu;

		spin_init(&spin, "sysctllocktest");
		for (i = spin_test_count; i > 0; --i) {
		    _spin_lock_quick(gd, &spin, "test");
		    spin_unlock_quick(gd, &spin);
		}
	}

        return (0);
}

SYSCTL_PROC(_debug, KERN_PROC_ALL, spin_lock_test, CTLFLAG_RW|CTLTYPE_INT,
        0, 0, sysctl_spin_lock_test, "I", "Test spinlock wait code");

#endif	/* INVARIANTS */
