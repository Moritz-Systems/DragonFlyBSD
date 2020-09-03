/*
 * Copyright (c) 2018-2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Maxime Villard.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NVMM_COMPAT_H_
#define _NVMM_COMPAT_H_

/*
 * This file contains API adaptations for DragonFly to the NetBSD APIs
 * used for NVMM.
 * XXX There are several APIs which have same name but different semantics
 * (for example kmem_alloc() and __BIT()), in those cases the DragonFly
 * one is #undef'fed and replaced by the one compatible with NetBSD
 * semantics.
 */

#ifdef __NetBSD__
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <uvm/uvm.h>
#include <uvm/uvm_page.h>

#define x86_cpuid_max_ext()	curcpu()->ci_max_ext_cpuid
#define x86_cpuid_ext_ecx(eax)	cpu_feature[3]
#define x86_cpuid2_value()	cpu_feature[1]
#define x86_idt_iv()		(uint64_t)curcpu()->ci_idtvec.iv_idt

#endif

#ifdef __DragonFly__
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/mutex2.h>
#include <sys/types.h>
#include <vm/vm_extern.h>
#include <vm/vm_pager.h>

#ifdef __x86_64__
#include <machine/npx.h>

#define fxsave			savexmm64
#define fx_cw			sv_env.en_cw
#define fx_sw			sv_env.en_sw
#define fx_tw			sv_env.en_tw
#define fx_zero			sv_env.en_zero
#define fx_mxcsr		sv_env.en_mxcsr
#define fx_mxcsr_mask		sv_env.en_mxcsr_mask

#define x86_fpu_mxcsr_mask	npx_mxcsr_mask

struct xsave_header {
	uint8_t xsh_fxsave[512];
	struct  xstate_hdr xsh_hdr;
};
#define xsh_xstate_bv		xsh_hdr.xstate_bv
#define xsh_xcomp_bv		xsh_hdr.xstate_xcomp_bv

/* Taken from NetBSD <x86/pmap.h> */
#define	PATENTRY(n, type)	(type << ((n) * 8))
#define	PAT_UC		0x0ULL
#define	PAT_WC		0x1ULL
#define	PAT_WT		0x4ULL
#define	PAT_WP		0x5ULL
#define	PAT_WB		0x6ULL
#define	PAT_UCMINUS	0x7ULL

/* system segments and gate types */
#define SDT_SYS286BSY	 3	/* system 286 TSS busy */

#define cpu_vendor	cpu_vendor_id
#define CPUVENDOR_AMD	CPU_VENDOR_AMD	

#define CPUID_PN	CPUID_PSN
#define CPUID_CFLUSH	CPUID_CLFSH
#define CPUID_SBF	CPUID_PBE
#define CPUID_LAHF	AMDID2_LAHF
#define CPUID_CMPLEGACY	AMDID2_CMP
#define CPUID_SVM	0x00000004	/* Secure Virtual Machine */
#define CPUID_ALTMOVCR0 AMDID2_CR8
#define CPUID_LZCNT	0x00000020	/* LZCNT instruction */
#define CPUID_SSE4A	AMDID2_SSE4A
#define CPUID_MISALIGNSSE	AMDID2_MAS
#define CPUID_3DNOWPF	AMDID2_PREFETCH
#define CPUID_IBS	AMDID2_IBS
#define CPUID_XOP	AMDID2_SSE5
#define CPUID_SKINIT	AMDID2_SKINIT
#define CPUID_WDT	AMDID2_WDT
#define CPUID_LWP	0x00008000	/* Light Weight Profiling */
#define CPUID_FMA4	0x00010000	/* FMA4 instructions */
#define CPUID_TCE	0x00020000	/* Translation cache Extension */
#define CPUID_NODEID	0x00080000	/* NodeID MSR available*/
#define CPUID_TBM	0x00200000	/* TBM instructions */
#define CPUID_TOPOEXT	AMDID2_TOPOEXT
#define CPUID_PCEC	0x00800000	/* Perf Ctr Ext Core */
#define CPUID_PCENB	0x01000000	/* Perf Ctr Ext NB */
#define CPUID_SPM	0x02000000	/* Stream Perf Mon */
#define CPUID_DBE	0x04000000	/* Data Breakpoint Extension */
#define CPUID_PTSC	0x08000000	/* PerfTsc */
#define CPUID_L2IPERFC	0x10000000	/* L2I performance counter Extension */
#define CPUID_SYSCALL	AMDID_SYSCALL
#define CPUID_MPC	AMDID_MP
#define CPUID_XD	AMDID_NX
#define CPUID_MMXX	AMDID_EXT_MMX
#define CPUID_FFXSR	AMDID_FFXSR
#define CPUID_P1GB	AMDID_PAGE1GB
#define CPUID_EM64T	CPUID_IA64
#define CPUID_3DNOW2	AMDID_EXT_3DNOW
#define CPUID_3DNOW	AMDID_3DNOW
#define CPUID2_PCLMUL	CPUID2_PCLMULQDQ
#define CPUID2_CID	CPUID2_CNXTID
#define CPUID2_SDBG	0x00000800	/* Silicon Debug */
#define CPUID2_FMA	0x00001000	/* has Fused Multiply Add */
#define CPUID2_xTPR	CPUID2_XTPR
#define CPUID2_MOVBE	0x00400000	/* MOVBE (move after byteswap) */
#define CPUID2_AES	CPUID2_AESNI
#define CPUID2_RAZ	CPUID2_VMM
#define CPUID2_PCID	0x00020000	/* Process Context ID */

#define CPUID_SEF_FSGSBASE	CPUID_STDEXT_FSGSBASE
#define CPUID_SEF_SGX		__BIT(2)  /* Software Guard Extensions */
#define CPUID_SEF_RTM		CPUID_STDEXT_RTM
#define CPUID_SEF_BMI1		CPUID_STDEXT_BMI1
#define CPUID_SEF_HLE		CPUID_STDEXT_HLE
#define CPUID_SEF_SMEP		CPUID_STDEXT_SMEP
#define CPUID_SEF_BMI2		CPUID_STDEXT_BMI2
#define CPUID_SEF_ERMS		CPUID_STDEXT_ENH_MOVSB
#define CPUID_SEF_FDPEXONLY	__BIT(6)  /* x87FPU Data ptr updated only on x87exp */
#define CPUID_SEF_FPUCSDS	__BIT(13) /* Deprecate FPU CS and FPU DS values */
#define CPUID_SEF_PQE		__BIT(15) /* Resource Director Technology Allocation */
#define CPUID_SEF_RDSEED	CPUID_STDEXT_RDSEED
#define CPUID_SEF_ADX		CPUID_STDEXT_ADX
#define CPUID_SEF_SMAP		CPUID_STDEXT_SMAP
#define CPUID_SEF_CLFLUSHOPT	__BIT(23) /* Cache Line FLUSH OPTimized */
#define CPUID_SEF_CLWB		__BIT(24) /* Cache Line Write Back */
#define CPUID_SEF_PREFETCHWT1	__BIT(0)  /* PREFETCHWT1 instruction */
#define CPUID_SEF_UMIP		__BIT(2)  /* User-Mode Instruction prevention */
#define CPUID_SEF_PKU		__BIT(3)  /* Protection Keys for User-mode pages */
#define CPUID_SEF_OSPKE		__BIT(4)  /* OS has set CR4.PKE to ena. protec. keys */
#define CPUID_SEF_WAITPKG	__BIT(5)  /* TPAUSE,UMONITOR,UMWAIT */
#define CPUID_SEF_GFNI		__BIT(8)
#define CPUID_SEF_VAES		__BIT(9)
#define CPUID_SEF_VPCLMULQDQ	__BIT(10)
#define CPUID_SEF_CLDEMOTE	__BIT(25) /* Cache line demote */
#define CPUID_SEF_MOVDIRI	__BIT(27) /* MOVDIRI instruction */
#define CPUID_SEF_MOVDIR64B	__BIT(28) /* MOVDIR64B instruction */
#define CPUID_SEF_SGXLC		__BIT(30) /* SGX Launch Configuration */
#define CPUID_SEF_INVPCID	CPUID_STDEXT_INVPCID
#define CPUID_SEF_L1D_FLUSH	__BIT(28) /* IA32_FLUSH_CMD MSR */

#define CPUID_PES1_XSAVEOPT	0x00000001	/* xsaveopt instruction */
#define CPUID_PES1_XSAVEC	0x00000002	/* xsavec & compacted XRSTOR */
#define CPUID_PES1_XGETBV	0x00000004	/* xgetbv with ECX = 1 */
#define CPUID_PES1_XSAVES	0x00000008	/* xsaves/xrstors, IA32_XSS */

#define CPUID_AMD_SVM_NP		0x00000001
#define CPUID_AMD_SVM_NRIPS		0x00000008
#define CPUID_AMD_SVM_FlushByASID	0x00000040
#define CPUID_AMD_SVM_DecodeAssist	0x00000080

/*
 * Intel CPUID Extended Topology Enumeration Fn0000000b
 * %ecx == level number
 *	%eax: See below.
 *	%ebx: Number of logical processors at this level.
 *	%ecx: See below.
 *	%edx: x2APIC ID of the current logical processor.
 */
/* %eax */
#define CPUID_TOP_SHIFTNUM	__BITS(4, 0) /* Topology ID shift value */
/* %ecx */
#define CPUID_TOP_LVLNUM	__BITS(7, 0) /* Level number */
#define CPUID_TOP_LVLTYPE	__BITS(15, 8) /* Level type */
#define CPUID_TOP_LVLTYPE_INVAL	0	 	/* Invalid */
#define CPUID_TOP_LVLTYPE_SMT	1	 	/* SMT */
#define CPUID_TOP_LVLTYPE_CORE	2	 	/* Core */

#define CR0_ET	0x00000010	/* Extension Type (387 (if set) vs 287) */
#define CR4_OSXSAVE	CR4_XSAVE
#define XCR0_X87	0x00000001	/* x87 FPU/MMX state */
#define XCR0_SSE	0x00000002	/* SSE state */

#define MSR_DE_CFG	0xc0011029
#define MSR_IC_CFG	0xc0011021
#define MSR_UCODE_AMD_PATCHLEVEL	0x0000008b
#define MSR_NB_CFG	0xc001001f
#define 	NB_CFG_INITAPICCPUIDLO	(1ULL << 54)
#define MSR_SFMASK	0xc0000084		/* flags to clear on syscall */
#define MSR_KERNELGSBASE 0xc0000102		/* storage for swapgs ins */
#define MSR_SYSENTER_CS		0x174	/* PII+ only */
#define MSR_SYSENTER_ESP	0x175	/* PII+ only */
#define MSR_SYSENTER_EIP	0x176	/* PII+ only */
#define MSR_CR_PAT		0x277
#define MSR_VMCR	0xc0010114	/* Virtual Machine Control Register */
#define 	VMCR_DPD	0x00000001	/* Debug port disable */
#define 	VMCR_RINIT	0x00000002	/* intercept init */
#define 	VMCR_DISA20	0x00000004	/* Disable A20 masking */
#define 	VMCR_LOCK	0x00000008	/* SVM Lock */
#define 	VMCR_SVMED	0x00000010	/* SVME Disable */

#define 	EFER_FFXSR	0x00004000	/* Fast FXSAVE/FXRSTOR En. */
#define 	EFER_TCE	0x00008000	/* Translation Cache Ext. */
#define MSR_IA32_ARCH_CAPABILITIES 0x10a
#define 	IA32_ARCH_RDCL_NO	0x01
#define 	IA32_ARCH_IBRS_ALL	0x02
#define 	IA32_ARCH_RSBA		0x04
#define 	IA32_ARCH_SKIP_L1DFL_VMENTRY 0x08
#define 	IA32_ARCH_IF_PSCHANGE_MC_NO 0x40
#define 	IA32_ARCH_TSX_CTRL	0x80
#define 	IA32_ARCH_TAA_NO	0x100
#define MSR_IA32_FLUSH_CMD	0x10b
#define 	IA32_FLUSH_CMD_L1D_FLUSH 0x01
#define MSR_MISC_ENABLE		0x1a0
#define 	IA32_MISC_FAST_STR_EN	__BIT(0)
#define 	IA32_MISC_ATCC_EN	__BIT(3)
#define 	IA32_MISC_PERFMON_EN	__BIT(7)
#define 	IA32_MISC_BTS_UNAVAIL	__BIT(11)
#define 	IA32_MISC_PEBS_UNAVAIL	__BIT(12)
#define 	IA32_MISC_EISST_EN	__BIT(16)
#define 	IA32_MISC_MWAIT_EN	__BIT(18)
#define 	IA32_MISC_LIMIT_CPUID	__BIT(22)
#define 	IA32_MISC_XTPR_DIS	__BIT(23)
#define 	IA32_MISC_XD_DIS	__BIT(34)

#define PGEX_X		PGEX_I

#define x86_cpuid_max_ext()	cpu_exthigh
#define x86_cpuid2_value()	cpu_feature2
#define cpuid_level		cpu_high
#define x86_xsave_features	x86_get_xsave_features()
/* XXX validate that the idt addr is correct this way */
#define x86_idt_iv()		r_idt_arr[mdcpu->mi.gd_cpuid].rd_base

static __inline void
x86_cpuid(uint32_t eax, uint32_t *regs)
{
	uint32_t p[4];
	memset(p, 0, sizeof(p));

	do_cpuid(eax, p);

	regs[0] = p[0]; 	/* %eax */
	regs[1] = p[1];		/* %ebx */
	regs[2] = p[2];		/* %ecx */
	regs[3] = p[3];		/* %edx */
}

static __inline void
x86_cpuid2(uint32_t eax, uint32_t ecx, uint32_t *regs)
{
	uint32_t p[4];
	memset(p, 0, sizeof(p));

	cpuid_count(eax, ecx, p);

	regs[0] = p[0];
	regs[1] = p[1];
	regs[2] = p[2];
	regs[3] = p[3];
}

static __inline uint32_t
x86_cpuid_ext_ecx(void)
{
	uint32_t p[4];
	memset(p, 0, sizeof(p));

	do_cpuid(0x80000001, p);

	return p[2];	/* %ecx */
}

static __inline uint64_t
x86_get_xsave_features(void)
{
#ifndef CPU_DISABLE_AVX
	if (cpu_xsave) {
		/* Copy of NetBSD cpu_probe_fpu() code for x86_xsave_features */
		u_int descs[4];
		x86_cpuid(0xd, descs);
		return (uint64_t)descs[3] << 32 | descs[0];
	}
	else
#endif
		return 0;
}

static __inline uint64_t
rdxcr(uint32_t xcr)
{
	uint32_t low, high;

	__asm volatile (
		"xgetbv"
		: "=a" (low), "=d" (high)
		: "c" (xcr)
	);

	return (low | ((uint64_t)high << 32));
}

static __inline void
wrxcr(uint32_t xcr, uint64_t val)
{
	uint32_t low, high;

	low = val;
	high = val >> 32;

	xsetbv(xcr, low, high);
}

static __inline void
load_cr2(u_long data)
{

	__asm __volatile("movq %0,%%cr2" : : "r" (data) : "memory");
}

#define lcr2(x)		load_cr2(x)
#define lcr4(x)		load_cr4(x)
#define ldr0(x)		load_dr0(x)
#define ldr1(x)		load_dr1(x)
#define ldr2(x)		load_dr2(x)
#define ldr3(x)		load_dr3(x)
#define ldr6(x)		load_dr6(x)
#define ldr7(x)		load_dr7(x)

#define CPU_INFO_ITERATOR		int
#define CPU_INFO_FOREACH(cii, ci)	\
	cii = 0; cii < ncpus && (ci = globaldata_find(cii)); cii++

#endif /* __x86_64__ */

typedef enum krw_t {
	RW_READER = 0,
	RW_WRITER = 1
} krw_t;
typedef vm_offset_t vaddr_t;
typedef vm_size_t vsize_t;
typedef size_t	psize_t;
typedef vm_offset_t voff_t;
typedef int uvm_flag_t;
typedef struct file file_t;
typedef u_int64_t uint64_t;
typedef vm_paddr_t paddr_t;
struct kcpuset;
typedef struct kcpuset kcpuset_t;

#define cpu_number()		mycpuid
#define curcpu()		mycpu
#define cpu_index(cpu)		(cpu)->gd_cpuid
#define cpu_info		globaldata

#undef KASSERT
#define	KASSERT(x)		KKASSERT(x)
#define kmutex_t		struct mtx
#define mutex_owned(lock)	mtx_owned(lock)
#define mutex_enter(lock)	mtx_lock(lock)
#define mutex_exit(lock)	mtx_unlock(lock)
#define mutex_init(lock, type, ipl)	mtx_init(lock, "nvmmmtx")
#define mutex_destroy(lock)	do {} while (0)
#define	printf			kprintf
#define	__cacheline_aligned	__cachealign
#define __arraycount(__x)	(sizeof(__x) / sizeof(__x[0]))
#define atomic_inc_uint(x)	atomic_add_int(x, 1)
#define atomic_dec_uint(x)	atomic_subtract_int(x, 1)
#define atomic_inc_64(x)	atomic_add_64(x, 1)
#define uimin(a, b)		umin(a, b)
#define kpreempt_disable()	crit_enter()
#define kpreempt_enable()	crit_exit()
#define kpreempt_disabled()	crit_test(curthread)

#ifdef _LP64
#define	__HAVE_ATOMIC64_LOADSTORE	1
#define	__ATOMIC_SIZE_MAX		8
#else
#define	__ATOMIC_SIZE_MAX		4
#endif

#define	__ATOMIC_PTR_CHECK(p) do					      \
{									      \
	CTASSERT(sizeof(*(p)) <= __ATOMIC_SIZE_MAX);			      \
	KASSERT(((uintptr_t)(p) & (sizeof(*(p)) - 1)) == 0);		      \
} while (0)
#define __BEGIN_ATOMIC_LOAD(p, v) \
	union { __typeof__(*(p)) __al_val; char __al_buf[1]; } v;
#define __END_ATOMIC_LOAD(v) \
	(v).__al_val

#define	atomic_load_relaxed(p)						      \
({									      \
	const volatile __typeof__(*(p)) *__al_ptr = (p);		      \
	__ATOMIC_PTR_CHECK(__al_ptr);					      \
	__BEGIN_ATOMIC_LOAD(__al_ptr, __al_val);			      \
	__END_ATOMIC_LOAD(__al_val);					      \
})

/* DragonFly uses mutext as RW lock too */
#define krwlock_t		struct mtx
#define rw_init(lock)		mtx_init(lock, "nvmmrw")
#define rw_enter(lock, op)			\
	if (op == RW_WRITER) {			\
		mtx_lock_ex(lock, 0, 0);	\
	} else {				\
		mtx_lock_sh(lock, 0, 0);	\
	}
#define rw_exit(lock)		mtx_unlock(lock)
#define rw_write_held(lock)	mtx_islocked_ex(lock)
#define rw_destroy(lock)	do {} while (0)

MALLOC_DECLARE(M_NVMM);
#define KM_SLEEP	0x00000001	/* can sleep */
#define KM_NOSLEEP	0x00000002	/* don't sleep */

#define kmem_alloc(size, flags)	({			\
		KKASSERT(flags == KM_SLEEP);		\
		kmalloc(size, M_NVMM, M_WAITOK);	\
	})
#define kmem_zalloc(size, flags)	({		\
		KKASSERT(flags == KM_SLEEP);		\
		kmalloc(size, M_NVMM, M_WAITOK|M_ZERO);	\
	})
#define kmem_free(data, size)	kfree(data, M_NVMM)

#define kernel_map		&kernel_map

static __inline void
uvm_deallocate(struct vm_map *map, vaddr_t start, vsize_t size)
{
	vm_map_remove(map, trunc_page(start), round_page(start + size));
}

static __inline struct vmspace *
uvmspace_alloc(vaddr_t vmin, vaddr_t vmax, bool topdown)
{
	KKASSERT(!topdown);
	return vmspace_alloc(vmin, vmax);
}
#define uvmspace_free(space)		vmspace_rel(space)

/* Anonymous object, simulate by using physical memore object */
#define uvm_object			vm_object

static __inline struct vm_object *
uao_create(voff_t size, int flags)
{
	struct vm_object *object;
	KKASSERT(flags == 0);

	/* Allocated same way as sysv_shm.c */
	object = phys_pager_alloc(NULL, size, VM_PROT_DEFAULT, 0);
	vm_object_clear_flag(object, OBJ_ONEMAPPING);
	vm_object_set_flag(object, OBJ_NOSPLIT);
	return object;
}

static __inline void
uao_detach(struct vm_object *object)
{
	vm_object_terminate(object);
}

static __inline void
uao_reference(struct vm_object *object)
{
	vm_object_reference_quick(object);
}

#define UVM_PROT_MASK	0x07	/* protection mask */
#define UVM_PROT_RW	VM_PROT_RW
#define UVM_PROT_RWX	VM_PROT_ALL

/* inherit codes */
#define UVM_INH_MASK	0x30	/* inherit mask */
#define UVM_INH_SHARE	0x00	/* "share" */
#define UVM_INH_COPY	0x10	/* "copy" */
#define UVM_INH_NONE	0x20	/* "none" */
#define UVM_INH_DONATE	0x30	/* "donate" << not used */

/* macros to extract info */
#define UVM_PROTECTION(X)	((X) & UVM_PROT_MASK)
#define UVM_INHERIT(X)		(((X) & UVM_INH_MASK) >> 4)
#define UVM_MAXPROTECTION(X)	(((X) >> 8) & UVM_PROT_MASK)
#define UVM_ADVICE(X)		(((X) >> 12) & UVM_ADV_MASK)

#define UVM_MAPFLAG(PROT,MAXPROT,INH,ADVICE,FLAGS) \
	(((MAXPROT) << 8)|(PROT)|(INH))

#define uvm_fault(m, a, p)	vm_fault(m, a, p, 0)

static __inline int
uvm_map(struct vm_map *map, vaddr_t *startp /* IN/OUT */, vsize_t size,
    struct uvm_object *uobj, voff_t uoffset, vsize_t align, uvm_flag_t flags)
{
	vm_offset_t addr;
	int count;
	int error;

	vm_map_lock(map);

	if ((error = vm_map_findspace(map, uoffset,
			     size, PAGE_SIZE, 0, &addr)) != 0) {
		goto out;
	}

	/* XXX bump uobj ref count before map_insert */

	/* XXX vm_map_inherit for INH_SHARE */

	error = vm_map_insert(map, &count,
		uobj, NULL,  
		(vm_offset_t)uoffset, NULL,
		addr, addr + size,
		VM_MAPTYPE_NORMAL, VM_SUBSYS_UNKNOWN /* XXX */,
		UVM_PROTECTION(flags), UVM_MAXPROTECTION(flags), 0);

out:
	vm_map_unlock(map);
	return error;
}

static __inline void
uvm_unmap(struct vm_map *map, vaddr_t start, vaddr_t end)
{
	vm_map_remove(map, start, end);
}

static __inline int
uvm_map_pageable(struct vm_map *map, vaddr_t start, vaddr_t end,
    bool new_pageable, int lockflags)
{
	int error;
	KKASSERT(lockflags == 0);

	if (new_pageable)
		error = vm_map_unwire(map, start, end, 0);
	else
		error = vm_map_wire(map, start, end, 0);

	return error;
}

#define dev_type_open(__x)	d_open_t __x

#define asm			__asm

#ifdef DIAGNOSTIC
#define	__diagused		/* nothing */
#else
#define __diagused		__unused
#endif

/*
 * A barrier to stop the optimizer from moving code or assume live
 * register values. This is gcc specific, the version is more or less
 * arbitrary, might work with older compilers.
 */
#if __GNUC_PREREQ__(2, 95) || defined(__lint__)
#define	__insn_barrier()	__asm __volatile("":::"memory")
#else
#define	__insn_barrier()	/* */
#endif

#define MAXCPUS			SMP_MAXCPU

#include <sys/bitops.h>
/* DragonFly bitops have separate 32-bit __BIT() and a 64-bit __BIT64() */
#undef __BIT
#define __BIT(__x)		__BIT64(__x)

/* XXX need to implemented or find proper mapping for following XXX */
#define fpu_kern_enter()	do {} while (0)
#define fpu_kern_leave()	do {} while (0)
#define fpu_area_save(fpu, mask)	do {} while (0)
#define fpu_area_restore(fpu, mask)	do {} while (0)
#define x86_dbregs_save(lwp)		do {} while (0)
#define x86_dbregs_restore(lwp)		do {} while (0)
#define uvm_km_alloc(map, size, align, flags)	0
#define uvm_km_free(map, addr, size, flags)	do {} while (0)
#define uvm_pagealloc(obj, off, anon, flags)	0
#define uvm_pagefree(pg)		do {} while (0)
#define pmap_kenter_pa(addr, size, prot, flags)	do {} while (0)
#define pmap_kremove(addr, size)	do {} while (0)
#define pmap_update(pmap)		do {} while (0)
#define pmap_tlb_shootdown(pmap, addr, pt, why)	do {} while (0)
#define pmap_ept_transform(pmap)	do {} while (0)
#define xc_broadcast(pri, func, arg1, arg2) 	0, (void)func
#define xc_unicast(pri, func, arg1, arg2, ci)	0, (void)func
#define xc_wait(xc)			do {} while (0)
#define curlwp_bind()			0
#define curlwp_bindx(bound)		(void)bound
/* use cpumask_t/CPUMASK_* for kcpuset? */
#define kcpuset_isset(set, cpuid)	(cpuid == 0) /* XXX bogus */
#define kcpuset_clear(set, cpuid)	(void)set
#define kcpuset_copy(set1, set2)	(void)set1
#define kcpuset_create(setp, fl)	(void)setp
#define kcpuset_destroy(set)		(void)&set
#define ilog2(n)			(int)n

/* XXX missing pmap hooks */
#define pm_pdirpa			pm_pml4		/* XXX bogus */

/* XXX missing curcpu hooks */
#define ci_tss				gd_cpuid	
#define ci_tss_sel			gd_cpuid	
#define ci_gdt				gd_cpuid	

static __inline int
uvm_pglistalloc(psize_t size, paddr_t low, paddr_t high, paddr_t alignment,
    paddr_t boundary, struct pglist *rlist, int nsegs, int waitok)
{
	panic("%s: not implemented", __func__);
	return 0;
}
/* XXX end if things which need to implemented XXX */

#endif /* __DragonFly__ */

#endif /* _NVMM_COMPAT_H_ */
