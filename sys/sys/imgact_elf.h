/*-
 * Copyright (c) 1995-1996 Søren Schmidt
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/sys/imgact_elf.h,v 1.17.2.1 2000/07/06 22:26:40 obrien Exp $
 */

#ifndef _SYS_IMGACT_ELF_H_
#define	_SYS_IMGACT_ELF_H_

#include <sys/elf_common.h>
#include <machine/elf.h>

#ifdef _KERNEL

#define	AUXARGS_ENTRY(pos, id, val) {suword64(pos++, id); suword64(pos++, val);}

struct lwp;
struct file;
struct vnode;

/*
 * Structure used to pass infomation from the loader to the
 * stack fixup routine.
 */
typedef struct {
	Elf_Sword	execfd;
	Elf_Size	phdr;
	Elf_Size	phent;
	Elf_Size	phnum;
	Elf_Size	pagesz;
	Elf_Size	base;
	Elf_Size	flags;
	Elf_Size	entry;
} __ElfN(Auxargs);

typedef struct {
	Elf_Note	hdr;
	const char *	vendor;
	int		flags;
	boolean_t	(*trans_osrel)(const Elf_Note *, int32_t *);
} Elf_Brandnote;

typedef struct {
	int brand;
	int machine;
	const char *compat_3_brand;	/* pre Binutils 2.10 method (FBSD 3) */
	const char *emul_path;
	const char *interp_path;
	struct sysentvec *sysvec;
	const char *interp_newpath;
	int flags;
	Elf_Brandnote *brand_note;
} __ElfN(Brandinfo);

__ElfType(Auxargs);
__ElfType(Brandinfo);

#define	MAX_BRANDS		8
#define	BI_CAN_EXEC_DYN		0x0001
#define	BI_BRAND_NOTE		0x0002  /* May have note.ABI-tag section. */
#define	BI_BRAND_NOTE_MANDATORY	0x0004  /* Must have note.ABI-tag section. */
#define	BN_CAN_FETCH_OSREL	0x0001  /* No longer used */
#define	BN_TRANSLATE_OSREL	0x0002  /* New osreldate function pointer */

int	__elfN(brand_inuse)        (Elf_Brandinfo *entry);
int	__elfN(insert_brand_entry) (Elf_Brandinfo *entry);
int	__elfN(remove_brand_entry) (Elf_Brandinfo *entry);
int	__elfN(dragonfly_fixup)    (register_t **, struct image_params *);
int	__elfN(coredump)           (struct lwp *, int, struct vnode *, off_t);

int     generic_elf_coredump       (struct lwp *lp, int sig, struct file *fp,
				    off_t limit);
extern Elf_Brandnote 	__elfN(dragonfly_brandnote);

#endif /* _KERNEL */

#endif /* !_SYS_IMGACT_ELF_H_ */
