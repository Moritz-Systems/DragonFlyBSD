/*-
 * Copyright (c) 2007 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Simon 'corecode' Schubert <corecode@fs.ei.tum.de>
 * by Thomas E. Spanjaard <tgen@netphreax.net>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
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
 * 
 * $DragonFly: src/sys/kern/kern_kinfo.c,v 1.12 2007/05/24 05:45:45 dillon Exp $
 */

/*
 * This is a source file used by both the kernel and libkvm.
 */

#ifndef _KERNEL
#define _KERNEL_STRUCTURES
#endif

#include <sys/proc.h>
#include <vm/vm_map.h>
#include <sys/kinfo.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/jail.h>
#include <sys/globaldata.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif


/*
 * Fill in a struct kinfo_proc.
 */
void
fill_kinfo_proc(struct proc *p, struct kinfo_proc *kp)
{
	struct session *sess = p->p_pgrp->pg_session;

	bzero(kp, sizeof(*kp));

	kp->kp_paddr = (uintptr_t)p;
	kp->kp_fd = (uintptr_t)p->p_fd;

	kp->kp_flags = p->p_flag;
	kp->kp_stat = p->p_stat;
	kp->kp_lock = p->p_lock;
	kp->kp_acflag = p->p_acflag;
	kp->kp_traceflag = p->p_traceflag;
	kp->kp_siglist = p->p_siglist;
	kp->kp_sigignore = p->p_sigignore;
	kp->kp_sigcatch = p->p_sigcatch;
	kp->kp_sigflag = p->p_sigacts->ps_flag;
	kp->kp_start = p->p_start;

	strncpy(kp->kp_comm, p->p_comm, sizeof(kp->kp_comm) - 1);
	kp->kp_comm[sizeof(kp->kp_comm) - 1] = 0;

	kp->kp_uid = p->p_ucred->cr_uid;
	kp->kp_ngroups = p->p_ucred->cr_ngroups;
	bcopy(p->p_ucred->cr_groups, kp->kp_groups,
	      NGROUPS * sizeof(kp->kp_groups[0]));
	kp->kp_ruid = p->p_ucred->cr_ruid;
	kp->kp_svuid = p->p_ucred->cr_svuid;
	kp->kp_rgid = p->p_ucred->cr_rgid;
	kp->kp_svgid = p->p_ucred->cr_svgid;

	kp->kp_pid = p->p_pid;
	if (p->p_oppid != 0)
		kp->kp_ppid = p->p_oppid;
	else
		kp->kp_ppid = p->p_pptr != NULL ? p->p_pptr->p_pid : -1;
	kp->kp_pgid = p->p_pgrp->pg_id;
	kp->kp_jobc = p->p_pgrp->pg_jobc;
	kp->kp_sid = sess->s_sid;
	bcopy(sess->s_login, kp->kp_login, MAXLOGNAME);
	if (sess->s_ttyvp != NULL)
		kp->kp_auxflags |= KI_CTTY;
	if (SESS_LEADER(p))
		kp->kp_auxflags |= KI_SLEADER;
	if (((p->p_flag & P_CONTROLT) != 0) && (sess->s_ttyp != NULL)) {
		kp->kp_tdev = dev2udev(sess->s_ttyp->t_dev);
		if (sess->s_ttyp->t_pgrp != NULL)
			kp->kp_tpgid = sess->s_ttyp->t_pgrp->pg_id;
		else
			kp->kp_tpgid = -1;
		if (sess->s_ttyp->t_session != NULL)
			kp->kp_tsid = sess->s_ttyp->t_session->s_sid;
		else
			kp->kp_tsid = -1;
	} else {
		kp->kp_tdev = NOUDEV;
	}
	kp->kp_exitstat = p->p_xstat;
	kp->kp_nthreads = p->p_nthreads;
	kp->kp_nice = p->p_nice;
	kp->kp_swtime = p->p_swtime;

	kp->kp_vm_map_size = p->p_vmspace->vm_map.size;
	kp->kp_vm_rssize = vmspace_resident_count(p->p_vmspace);
	kp->kp_vm_swrss = p->p_vmspace->vm_swrss;
	kp->kp_vm_tsize = p->p_vmspace->vm_tsize;
	kp->kp_vm_dsize = p->p_vmspace->vm_dsize;
	kp->kp_vm_ssize = p->p_vmspace->vm_ssize;

	if (jailed(p->p_ucred))
		kp->kp_jailid = p->p_ucred->cr_prison->pr_id;

	kp->kp_ru = p->p_ru;
	kp->kp_ru = p->p_cru;
}

/*
 * Fill in a struct kinfo_lwp.
 */
void
fill_kinfo_lwp(struct lwp *lwp, struct kinfo_lwp *kl)
{
	bzero(kl, sizeof(*kl));

	kl->kl_pid = lwp->lwp_proc->p_pid;
	kl->kl_tid = lwp->lwp_tid;

	kl->kl_flags = lwp->lwp_flag;
	kl->kl_stat = lwp->lwp_stat;
	kl->kl_lock = lwp->lwp_lock;
	kl->kl_tdflags = lwp->lwp_thread->td_flags;
#ifdef SMP
	kl->kl_mpcount = lwp->lwp_thread->td_mpcount;
#else
	kl->kl_mpcount = 0;
#endif

	kl->kl_prio = lwp->lwp_usdata.bsd4.priority;	/* XXX TGEN dangerous assumption */
	kl->kl_tdprio = lwp->lwp_thread->td_pri;
	kl->kl_rtprio = lwp->lwp_rtprio;

	kl->kl_uticks = lwp->lwp_thread->td_uticks;
	kl->kl_sticks = lwp->lwp_thread->td_sticks;
	kl->kl_iticks = lwp->lwp_thread->td_iticks;
	kl->kl_cpticks = lwp->lwp_cpticks;
	kl->kl_pctcpu = lwp->lwp_pctcpu;
	kl->kl_slptime = lwp->lwp_slptime;
	kl->kl_origcpu = lwp->lwp_usdata.bsd4.origcpu;	/* XXX TGEN same */
	kl->kl_estcpu = lwp->lwp_usdata.bsd4.estcpu;
	kl->kl_cpuid = lwp->lwp_thread->td_gd->gd_cpuid;

	kl->kl_ru = lwp->lwp_ru;

	kl->kl_siglist = lwp->lwp_siglist;
	kl->kl_sigmask = lwp->lwp_sigmask;

	kl->kl_wchan = (uintptr_t)lwp->lwp_thread->td_wchan;
	if (lwp->lwp_thread->td_wmesg) {
		strncpy(kl->kl_wmesg, lwp->lwp_thread->td_wmesg, WMESGLEN);
		kl->kl_wmesg[WMESGLEN] = 0;
	}
}

/*
 * Fill in a struct kinfo_proc for kernel threads (i.e. those without proc).
 */
void
fill_kinfo_proc_kthread(struct thread *td, struct kinfo_proc *kp)
{
	bzero(kp, sizeof(*kp));

	/*
	 * Fill in fake proc information and semi-fake lwp info.
	 */
	kp->kp_pid = -1;
	kp->kp_tdev = NOUDEV;
	strncpy(kp->kp_comm, td->td_comm, sizeof(kp->kp_comm) - 1);
	kp->kp_comm[sizeof(kp->kp_comm) - 1] = 0;
	kp->kp_flags = P_SYSTEM;
	kp->kp_stat = SACTIVE;

	kp->kp_lwp.kl_pid = -1;
	kp->kp_lwp.kl_tid = (uintptr_t)td;
	kp->kp_lwp.kl_tdflags = td->td_flags;
#ifdef SMP
	kp->kp_lwp.kl_mpcount = td->td_mpcount;
#else /* !SMP */
	kp->kp_lwp.kl_mpcount = 0;
#endif /* SMP */

	kp->kp_lwp.kl_tdprio = td->td_pri;
	kp->kp_lwp.kl_rtprio.type = RTP_PRIO_THREAD;
	kp->kp_lwp.kl_rtprio.prio = td->td_pri & TDPRI_MASK;

	kp->kp_lwp.kl_uticks = td->td_uticks;
	kp->kp_lwp.kl_sticks = td->td_sticks;
	kp->kp_lwp.kl_iticks = td->td_iticks;
	kp->kp_lwp.kl_cpuid = td->td_gd->gd_cpuid;

	kp->kp_lwp.kl_wchan = (uintptr_t)td->td_wchan;
	if (td->td_flags & TDF_RUNQ)
		kp->kp_lwp.kl_stat = LSRUN;
	else 
		kp->kp_lwp.kl_stat = LSSLEEP;
	if (td->td_wmesg) {
		strncpy(kp->kp_lwp.kl_wmesg, td->td_wmesg, WMESGLEN);
		kp->kp_lwp.kl_wmesg[WMESGLEN] = 0;
	}
}
