/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
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
 * $DragonFly: src/sys/vfs/hammer/hammer_mirror.c,v 1.12 2008/07/11 05:44:23 dillon Exp $
 */
/*
 * HAMMER mirroring ioctls - serialize and deserialize modifications made
 *			     to a filesystem.
 */

#include "hammer.h"

static int hammer_mirror_check(hammer_cursor_t cursor,
				struct hammer_ioc_mrecord_rec *mrec);
static int hammer_mirror_update(hammer_cursor_t cursor,
				struct hammer_ioc_mrecord_rec *mrec);
static int hammer_mirror_write(hammer_cursor_t cursor,
				struct hammer_ioc_mrecord_rec *mrec,
				char *udata);
static int hammer_ioc_mirror_write_rec(hammer_cursor_t cursor,
				struct hammer_ioc_mrecord_rec *mrec,
				struct hammer_ioc_mirror_rw *mirror,
				u_int32_t localization,
				char *uptr);
static int hammer_ioc_mirror_write_pass(hammer_cursor_t cursor,
				struct hammer_ioc_mrecord_rec *mrec,
				struct hammer_ioc_mirror_rw *mirror,
				u_int32_t localization);
static int hammer_ioc_mirror_write_skip(hammer_cursor_t cursor,
				struct hammer_ioc_mrecord_skip *mrec,
				struct hammer_ioc_mirror_rw *mirror,
				u_int32_t localization);
static int hammer_mirror_delete_at_cursor(hammer_cursor_t cursor,
			        struct hammer_ioc_mirror_rw *mirror);
static int hammer_mirror_localize_data(hammer_data_ondisk_t data,
				hammer_btree_leaf_elm_t leaf);

/*
 * All B-Tree records within the specified key range which also conform
 * to the transaction id range are returned.  Mirroring code keeps track
 * of the last transaction id fully scanned and can efficiently pick up
 * where it left off if interrupted.
 *
 * The PFS is identified in the mirror structure.  The passed ip is just
 * some directory in the overall HAMMER filesystem and has nothing to
 * do with the PFS.
 */
int
hammer_ioc_mirror_read(hammer_transaction_t trans, hammer_inode_t ip,
		       struct hammer_ioc_mirror_rw *mirror)
{
	struct hammer_cmirror cmirror;
	struct hammer_cursor cursor;
	union hammer_ioc_mrecord_any mrec;
	hammer_btree_leaf_elm_t elm;
	const int crc_start = HAMMER_MREC_CRCOFF;
	char *uptr;
	int error;
	int data_len;
	int bytes;
	int eatdisk;
	u_int32_t localization;
	u_int32_t rec_crc;

	localization = (u_int32_t)mirror->pfs_id << 16;

	if ((mirror->key_beg.localization | mirror->key_end.localization) &
	    HAMMER_LOCALIZE_PSEUDOFS_MASK) {
		return(EINVAL);
	}
	if (hammer_btree_cmp(&mirror->key_beg, &mirror->key_end) > 0)
		return(EINVAL);

	mirror->key_cur = mirror->key_beg;
	mirror->key_cur.localization &= HAMMER_LOCALIZE_MASK;
	mirror->key_cur.localization += localization;
	bzero(&mrec, sizeof(mrec));
	bzero(&cmirror, sizeof(cmirror));

retry:
	error = hammer_init_cursor(trans, &cursor, NULL, NULL);
	if (error) {
		hammer_done_cursor(&cursor);
		goto failed;
	}
	cursor.key_beg = mirror->key_cur;
	cursor.key_end = mirror->key_end;
	cursor.key_end.localization &= HAMMER_LOCALIZE_MASK;
	cursor.key_end.localization += localization;

	cursor.flags |= HAMMER_CURSOR_END_INCLUSIVE;
	cursor.flags |= HAMMER_CURSOR_BACKEND;

	/*
	 * This flag filters the search to only return elements whos create
	 * or delete TID is >= mirror_tid.  The B-Tree uses the mirror_tid
	 * field stored with internal and leaf nodes to shortcut the scan.
	 */
	cursor.flags |= HAMMER_CURSOR_MIRROR_FILTERED;
	cursor.cmirror = &cmirror;
	cmirror.mirror_tid = mirror->tid_beg;

	error = hammer_btree_first(&cursor);
	while (error == 0) {
		/*
		 * Yield to more important tasks
		 */
		if (error == 0) {
			error = hammer_signal_check(trans->hmp);
			if (error)
				break;
		}

		/*
		 * An internal node can be returned in mirror-filtered
		 * mode and indicates that the scan is returning a skip
		 * range in the cursor->cmirror structure.
		 */
		uptr = (char *)mirror->ubuf + mirror->count;
		if (cursor.node->ondisk->type == HAMMER_BTREE_TYPE_INTERNAL) {
			/*
			 * Check space
			 */
			mirror->key_cur = cmirror.skip_beg;
			bytes = sizeof(mrec.skip);
			if (mirror->count + HAMMER_HEAD_DOALIGN(bytes) >
			    mirror->size) {
				break;
			}

			/*
			 * Fill mrec
			 */
			mrec.head.signature = HAMMER_IOC_MIRROR_SIGNATURE;
			mrec.head.type = HAMMER_MREC_TYPE_SKIP;
			mrec.head.rec_size = bytes;
			mrec.skip.skip_beg = cmirror.skip_beg;
			mrec.skip.skip_end = cmirror.skip_end;
			mrec.head.rec_crc = crc32(&mrec.head.rec_size,
						 bytes - crc_start);
			error = copyout(&mrec, uptr, bytes);
			eatdisk = 0;
			goto didwrite;
		}

		/*
		 * Leaf node.  In full-history mode we could filter out
		 * elements modified outside the user-requested TID range.
		 *
		 * However, such elements must be returned so the writer
		 * can compare them against the target to detemrine what
		 * needs to be deleted on the target, particular for
		 * no-history mirrors.
		 */
		KKASSERT(cursor.node->ondisk->type == HAMMER_BTREE_TYPE_LEAF);
		elm = &cursor.node->ondisk->elms[cursor.index].leaf;
		mirror->key_cur = elm->base;

		if ((elm->base.create_tid < mirror->tid_beg ||
		    elm->base.create_tid > mirror->tid_end) &&
		    (elm->base.delete_tid < mirror->tid_beg ||
		    elm->base.delete_tid > mirror->tid_end)) {
			bytes = sizeof(mrec.rec);
			if (mirror->count + HAMMER_HEAD_DOALIGN(bytes) >
			    mirror->size) {
				break;
			}

			/*
			 * Fill mrec.  PASS records are records which are
			 * outside the TID range needed for the mirror
			 * update.  They are sent without any data payload
			 * because the mirroring target must still compare
			 * records that fall outside the SKIP ranges to
			 * determine what might need to be deleted.  Such
			 * deletions are needed if the master or files on
			 * the master are no-history, or if the slave is
			 * so far behind the master has already been pruned.
			 */
			mrec.head.signature = HAMMER_IOC_MIRROR_SIGNATURE;
			mrec.head.type = HAMMER_MREC_TYPE_PASS;
			mrec.head.rec_size = bytes;
			mrec.rec.leaf = *elm;
			mrec.head.rec_crc = crc32(&mrec.head.rec_size,
						 bytes - crc_start);
			error = copyout(&mrec, uptr, bytes);
			eatdisk = 1;
			goto didwrite;
			
		}

		/*
		 * The core code exports the data to userland.
		 */
		data_len = (elm->data_offset) ? elm->data_len : 0;
		if (data_len) {
			error = hammer_btree_extract(&cursor,
						     HAMMER_CURSOR_GET_DATA);
			if (error)
				break;
		}

		bytes = sizeof(mrec.rec) + data_len;
		if (mirror->count + HAMMER_HEAD_DOALIGN(bytes) > mirror->size)
			break;

		/*
		 * Construct the record for userland and copyout.
		 *
		 * The user is asking for a snapshot, if the record was
		 * deleted beyond the user-requested ending tid, the record
		 * is not considered deleted from the point of view of
		 * userland and delete_tid is cleared.
		 */
		mrec.head.signature = HAMMER_IOC_MIRROR_SIGNATURE;
		mrec.head.type = HAMMER_MREC_TYPE_REC;
		mrec.head.rec_size = bytes;
		mrec.rec.leaf = *elm;
		if (elm->base.delete_tid >= mirror->tid_end)
			mrec.rec.leaf.base.delete_tid = 0;
		rec_crc = crc32(&mrec.head.rec_size,
				sizeof(mrec.rec) - crc_start);
		if (data_len)
			rec_crc = crc32_ext(cursor.data, data_len, rec_crc);
		mrec.head.rec_crc = rec_crc;
		error = copyout(&mrec, uptr, sizeof(mrec.rec));
		if (data_len && error == 0) {
			error = copyout(cursor.data, uptr + sizeof(mrec.rec),
					data_len);
		}
		eatdisk = 1;

		/*
		 * eatdisk controls whether we skip the current cursor
		 * position on the next scan or not.  If doing a SKIP
		 * the cursor is already positioned properly for the next
		 * scan and eatdisk will be 0.
		 */
didwrite:
		if (error == 0) {
			mirror->count += HAMMER_HEAD_DOALIGN(bytes);
			if (eatdisk)
				cursor.flags |= HAMMER_CURSOR_ATEDISK;
			else
				cursor.flags &= ~HAMMER_CURSOR_ATEDISK;
			error = hammer_btree_iterate(&cursor);
		}
	}
	if (error == ENOENT) {
		mirror->key_cur = mirror->key_end;
		error = 0;
	}
	hammer_done_cursor(&cursor);
	if (error == EDEADLK)
		goto retry;
	if (error == EINTR) {
		mirror->head.flags |= HAMMER_IOC_HEAD_INTR;
		error = 0;
	}
failed:
	mirror->key_cur.localization &= HAMMER_LOCALIZE_MASK;
	return(error);
}

/*
 * Copy records from userland to the target mirror.
 *
 * The PFS is identified in the mirror structure.  The passed ip is just
 * some directory in the overall HAMMER filesystem and has nothing to
 * do with the PFS.  In fact, there might not even be a root directory for
 * the PFS yet!
 */
int
hammer_ioc_mirror_write(hammer_transaction_t trans, hammer_inode_t ip,
		       struct hammer_ioc_mirror_rw *mirror)
{
	union hammer_ioc_mrecord_any mrec;
	struct hammer_cursor cursor;
	u_int32_t localization;
	int checkspace_count = 0;
	int error;
	int bytes;
	char *uptr;
	int seq;

	localization = (u_int32_t)mirror->pfs_id << 16;
	seq = trans->hmp->flusher.act;

	/*
	 * Validate the mirror structure and relocalize the tracking keys.
	 */
	if (mirror->size < 0 || mirror->size > 0x70000000)
		return(EINVAL);
	mirror->key_beg.localization &= HAMMER_LOCALIZE_MASK;
	mirror->key_beg.localization += localization;
	mirror->key_end.localization &= HAMMER_LOCALIZE_MASK;
	mirror->key_end.localization += localization;
	mirror->key_cur.localization &= HAMMER_LOCALIZE_MASK;
	mirror->key_cur.localization += localization;

	/*
	 * Set up our tracking cursor for the loop.  The tracking cursor
	 * is used to delete records that are no longer present on the
	 * master.  The last handled record at key_cur must be skipped.
	 */
	error = hammer_init_cursor(trans, &cursor, NULL, NULL);

	cursor.key_beg = mirror->key_cur;
	cursor.key_end = mirror->key_end;
	cursor.flags |= HAMMER_CURSOR_BACKEND;
	error = hammer_btree_first(&cursor);
	if (error == 0)
		cursor.flags |= HAMMER_CURSOR_ATEDISK;
	if (error == ENOENT)
		error = 0;

	/*
	 * Loop until our input buffer has been exhausted.
	 */
	while (error == 0 &&
		mirror->count + sizeof(mrec.head) <= mirror->size) {

	        /*
		 * Don't blow out the buffer cache.  Leave room for frontend
		 * cache as well.
		 */
		if (hammer_flusher_meta_halflimit(trans->hmp) ||
		    hammer_flusher_undo_exhausted(trans, 1)) {
			hammer_unlock_cursor(&cursor, 0);
			hammer_flusher_wait(trans->hmp, seq);
			hammer_lock_cursor(&cursor, 0);
			seq = hammer_flusher_async(trans->hmp);
		}

		/*
		 * If there is insufficient free space it may be due to
		 * reserved bigblocks, which flushing might fix.
		 */
		if (hammer_checkspace(trans->hmp, HAMMER_CHKSPC_MIRROR)) {
			if (++checkspace_count == 10) {
				error = ENOSPC;
				break;
			}
			hammer_unlock_cursor(&cursor, 0);
			hammer_flusher_wait(trans->hmp, seq);
			hammer_lock_cursor(&cursor, 0);
			seq = hammer_flusher_async(trans->hmp);
		}


		/*
		 * Acquire and validate header
		 */
		if ((bytes = mirror->size - mirror->count) > sizeof(mrec))
			bytes = sizeof(mrec);
		uptr = (char *)mirror->ubuf + mirror->count;
		error = copyin(uptr, &mrec, bytes);
		if (error)
			break;
		if (mrec.head.signature != HAMMER_IOC_MIRROR_SIGNATURE) {
			error = EINVAL;
			break;
		}
		if (mrec.head.rec_size < sizeof(mrec.head) ||
		    mrec.head.rec_size > sizeof(mrec) + HAMMER_XBUFSIZE ||
		    mirror->count + mrec.head.rec_size > mirror->size) {
			error = EINVAL;
			break;
		}

		switch(mrec.head.type) {
		case HAMMER_MREC_TYPE_SKIP:
			if (mrec.head.rec_size != sizeof(mrec.skip))
				error = EINVAL;
			if (error == 0)
				error = hammer_ioc_mirror_write_skip(&cursor, &mrec.skip, mirror, localization);
			break;
		case HAMMER_MREC_TYPE_REC:
			if (mrec.head.rec_size < sizeof(mrec.rec))
				error = EINVAL;
			if (error == 0)
				error = hammer_ioc_mirror_write_rec(&cursor, &mrec.rec, mirror, localization, uptr + sizeof(mrec.rec));
			break;
		case HAMMER_MREC_TYPE_PASS:
			if (mrec.head.rec_size != sizeof(mrec.rec))
				error = EINVAL;
			if (error == 0)
				error = hammer_ioc_mirror_write_pass(&cursor, &mrec.rec, mirror, localization);
			break;
		default:
			error = EINVAL;
			break;
		}

		/*
		 * Retry the current record on deadlock, otherwise setup
		 * for the next loop.
		 */
		if (error == EDEADLK) {
			while (error == EDEADLK) {
				hammer_recover_cursor(&cursor);
				error = hammer_cursor_upgrade(&cursor);
			}
		} else {
			if (error == EALREADY)
				error = 0;
			if (error == 0) {
				mirror->count += 
					HAMMER_HEAD_DOALIGN(mrec.head.rec_size);
			}
		}
	}
	hammer_done_cursor(&cursor);

	/*
	 * cumulative error 
	 */
	if (error) {
		mirror->head.flags |= HAMMER_IOC_HEAD_ERROR;
		mirror->head.error = error;
	}

	/*
	 * ioctls don't update the RW data structure if an error is returned,
	 * always return 0.
	 */
	return(0);
}

/*
 * Handle skip records.
 *
 * We must iterate from the last resolved record position at mirror->key_cur
 * to skip_beg and delete any records encountered.
 *
 * mirror->key_cur must be carefully set when we succeed in processing
 * this mrec.
 */
static int
hammer_ioc_mirror_write_skip(hammer_cursor_t cursor,
			     struct hammer_ioc_mrecord_skip *mrec,
			     struct hammer_ioc_mirror_rw *mirror,
			     u_int32_t localization)
{
	int error;

	/*
	 * Relocalize the skip range
	 */
	mrec->skip_beg.localization &= HAMMER_LOCALIZE_MASK;
	mrec->skip_beg.localization += localization;
	mrec->skip_end.localization &= HAMMER_LOCALIZE_MASK;
	mrec->skip_end.localization += localization;

	/*
	 * Iterate from current position to skip_beg, deleting any records
	 * we encounter.
	 */
	cursor->key_end = mrec->skip_beg;
	cursor->flags |= HAMMER_CURSOR_BACKEND;

	error = hammer_btree_iterate(cursor);
	while (error == 0) {
		error = hammer_mirror_delete_at_cursor(cursor, mirror);
		if (error == 0)
			error = hammer_btree_iterate(cursor);
	}

	/*
	 * ENOENT just means we hit the end of our iteration.
	 */
	if (error == ENOENT)
		error = 0;

	/*
	 * Now skip past the skip (which is the whole point point of
	 * having a skip record).  The sender has not sent us any records
	 * for the skip area so we wouldn't know what to keep and what
	 * to delete anyway.
	 *
	 * Clear ATEDISK because skip_end is non-inclusive, so we can't
	 * count an exact match if we happened to get one.
	 */
	if (error == 0) {
		mirror->key_cur = mrec->skip_end;
		cursor->key_beg = mrec->skip_end;
		error = hammer_btree_lookup(cursor);
		cursor->flags &= ~HAMMER_CURSOR_ATEDISK;
		if (error == ENOENT)
			error = 0;
	}
	return(error);
}

/*
 * Handle B-Tree records.
 *
 * We must iterate to mrec->base.key (non-inclusively), and then process
 * the record.  We are allowed to write a new record or delete an existing
 * record, but cannot replace an existing record.
 *
 * mirror->key_cur must be carefully set when we succeed in processing
 * this mrec.
 */
static int
hammer_ioc_mirror_write_rec(hammer_cursor_t cursor,
			    struct hammer_ioc_mrecord_rec *mrec,
			    struct hammer_ioc_mirror_rw *mirror,
			    u_int32_t localization,
			    char *uptr)
{
	hammer_transaction_t trans;
	u_int32_t rec_crc;
	int error;

	trans = cursor->trans;
	rec_crc = crc32(mrec, sizeof(*mrec));

	if (mrec->leaf.data_len < 0 || 
	    mrec->leaf.data_len > HAMMER_XBUFSIZE ||
	    mrec->leaf.data_len + sizeof(*mrec) > mrec->head.rec_size) {
		return(EINVAL);
	}

	/*
	 * Re-localize for target.  relocalization of data is handled
	 * by hammer_mirror_write().
	 */
	mrec->leaf.base.localization &= HAMMER_LOCALIZE_MASK;
	mrec->leaf.base.localization += localization;

	/*
	 * Delete records through until we reach (non-inclusively) the
	 * target record.
	 */
	cursor->key_end = mrec->leaf.base;
	cursor->flags &= ~HAMMER_CURSOR_END_INCLUSIVE;
	cursor->flags |= HAMMER_CURSOR_BACKEND;

	error = hammer_btree_iterate(cursor);
	while (error == 0) {
		error = hammer_mirror_delete_at_cursor(cursor, mirror);
		if (error == 0)
			error = hammer_btree_iterate(cursor);
	}
	if (error == ENOENT)
		error = 0;

	/*
	 * Locate the record.
	 *
	 * If the record exists only the delete_tid may be updated.
	 *
	 * If the record does not exist we create it.  For now we
	 * ignore records with a non-zero delete_tid.  Note that
	 * mirror operations are effective an as-of operation and
	 * delete_tid can be 0 for mirroring purposes even if it is
	 * not actually 0 at the originator.
	 *
	 * These functions can return EDEADLK
	 */
	cursor->key_beg = mrec->leaf.base;
	cursor->flags |= HAMMER_CURSOR_BACKEND;
	cursor->flags &= ~HAMMER_CURSOR_INSERT;
	error = hammer_btree_lookup(cursor);

	if (error == 0 && hammer_mirror_check(cursor, mrec)) {
		error = hammer_mirror_update(cursor, mrec);
	} else if (error == ENOENT && mrec->leaf.base.delete_tid == 0) {
		error = hammer_mirror_write(cursor, mrec, uptr);
	} else if (error == ENOENT) {
		error = 0;
	}
	if (error == 0 || error == EALREADY)
		mirror->key_cur = mrec->leaf.base;
	return(error);
}

/*
 * This works like write_rec but no write or update is necessary,
 * and no data payload is included so we couldn't do a write even
 * if we wanted to.
 *
 * We must still iterate for deletions, and we can validate the
 * record header which is a good way to test for corrupted mirror
 * targets XXX.
 *
 * mirror->key_cur must be carefully set when we succeed in processing
 * this mrec.
 */
static
int
hammer_ioc_mirror_write_pass(hammer_cursor_t cursor,
			     struct hammer_ioc_mrecord_rec *mrec,
			     struct hammer_ioc_mirror_rw *mirror,
			     u_int32_t localization)
{
	hammer_transaction_t trans;
	u_int32_t rec_crc;
	int error;

	trans = cursor->trans;
	rec_crc = crc32(mrec, sizeof(*mrec));

	/*
	 * Re-localize for target.  Relocalization of data is handled
	 * by hammer_mirror_write().
	 */
	mrec->leaf.base.localization &= HAMMER_LOCALIZE_MASK;
	mrec->leaf.base.localization += localization;

	/*
	 * Delete records through until we reach (non-inclusively) the
	 * target record.
	 */
	cursor->key_end = mrec->leaf.base;
	cursor->flags &= ~HAMMER_CURSOR_END_INCLUSIVE;
	cursor->flags |= HAMMER_CURSOR_BACKEND;

	error = hammer_btree_iterate(cursor);
	while (error == 0) {
		error = hammer_mirror_delete_at_cursor(cursor, mirror);
		if (error == 0)
			error = hammer_btree_iterate(cursor);
	}
	if (error == ENOENT)
		error = 0;

	/*
	 * Locate the record and get past it by setting ATEDISK.
	 */
	if (error == 0) {
		mirror->key_cur = mrec->leaf.base;
		cursor->key_beg = mrec->leaf.base;
		cursor->flags |= HAMMER_CURSOR_BACKEND;
		cursor->flags &= ~HAMMER_CURSOR_INSERT;
		error = hammer_btree_lookup(cursor);
		if (error == 0)
			cursor->flags |= HAMMER_CURSOR_ATEDISK;
		else
			cursor->flags &= ~HAMMER_CURSOR_ATEDISK;
		if (error == ENOENT)
			error = 0;
	}
	return(error);
}

/*
 * As part of the mirror write we iterate across swaths of records
 * on the target which no longer exist on the source, and mark them
 * deleted.
 */
static
int
hammer_mirror_delete_at_cursor(hammer_cursor_t cursor,
			       struct hammer_ioc_mirror_rw *mirror)
{
	hammer_transaction_t trans;
	hammer_btree_elm_t elm;
	int error;

	if ((error = hammer_cursor_upgrade(cursor)) != 0)
		return(error);

	elm = &cursor->node->ondisk->elms[cursor->index];
	KKASSERT(elm->leaf.base.btype == HAMMER_BTREE_TYPE_RECORD);

	trans = cursor->trans;
	hammer_sync_lock_sh(trans);

	if (elm->leaf.base.delete_tid == 0) {
		/*
		 * We don't know when the originator deleted the element
		 * because it was destroyed, tid_end works.
		 */
		KKASSERT(elm->base.create_tid < mirror->tid_end);
		hammer_modify_node(trans, cursor->node, elm, sizeof(*elm));
		elm->base.delete_tid = mirror->tid_end;
		elm->leaf.delete_ts = time_second;
		hammer_modify_node_done(cursor->node);

		/*
		 * Track a count of active inodes.
		 */
		if (elm->base.obj_type == HAMMER_RECTYPE_INODE) {
			hammer_modify_volume_field(trans,
						   trans->rootvol,
						   vol0_stat_inodes);
			--trans->hmp->rootvol->ondisk->vol0_stat_inodes;
			hammer_modify_volume_done(trans->rootvol);
		}
	}
	hammer_sync_unlock(trans);

	cursor->flags |= HAMMER_CURSOR_ATEDISK;

	return(0);
}

/*
 * Check whether an update is needed in the case where a match already
 * exists on the target.  The only type of update allowed in this case
 * is an update of the delete_tid.
 *
 * Return non-zero if the update should proceed.
 */
static
int
hammer_mirror_check(hammer_cursor_t cursor, struct hammer_ioc_mrecord_rec *mrec)
{
	hammer_btree_leaf_elm_t leaf = cursor->leaf;

	if (leaf->base.delete_tid != mrec->leaf.base.delete_tid) {
		if (mrec->leaf.base.delete_tid != 0)
			return(1);
	}
	return(0);
}

/*
 * Update a record in-place.  Only the delete_tid can change.
 */
static
int
hammer_mirror_update(hammer_cursor_t cursor,
		     struct hammer_ioc_mrecord_rec *mrec)
{
	hammer_transaction_t trans;
	hammer_btree_leaf_elm_t elm;
	int error;

	if ((error = hammer_cursor_upgrade(cursor)) != 0)
		return(error);

	elm = cursor->leaf;
	trans = cursor->trans;

	if (mrec->leaf.base.delete_tid == 0) {
		kprintf("mirror_write: object %016llx:%016llx deleted on "
			"target, not deleted on source\n",
			elm->base.obj_id, elm->base.key);
		return(0);
	}
	hammer_sync_lock_sh(trans);

	KKASSERT(elm->base.create_tid < mrec->leaf.base.delete_tid);
	hammer_modify_node(trans, cursor->node, elm, sizeof(*elm));
	elm->base.delete_tid = mrec->leaf.base.delete_tid;
	elm->delete_ts = mrec->leaf.delete_ts;
	hammer_modify_node_done(cursor->node);

	/*
	 * Cursor is left on the current element, we want to skip it now.
	 */
	cursor->flags |= HAMMER_CURSOR_ATEDISK;

	/*
	 * Track a count of active inodes.
	 */
	if (elm->base.obj_type == HAMMER_RECTYPE_INODE) {
		hammer_modify_volume_field(trans,
					   trans->rootvol,
					   vol0_stat_inodes);
		--trans->hmp->rootvol->ondisk->vol0_stat_inodes;
		hammer_modify_volume_done(trans->rootvol);
	}
	hammer_sync_unlock(trans);

	return(0);
}

/*
 * Write out a new record.
 */
static
int
hammer_mirror_write(hammer_cursor_t cursor,
		    struct hammer_ioc_mrecord_rec *mrec,
		    char *udata)
{
	hammer_transaction_t trans;
	hammer_buffer_t data_buffer;
	hammer_off_t ndata_offset;
	hammer_tid_t high_tid;
	void *ndata;
	int error;
	int doprop;

	trans = cursor->trans;
	data_buffer = NULL;

	/*
	 * Get the sync lock so the whole mess is atomic
	 */
	hammer_sync_lock_sh(trans);

	/*
	 * Allocate and adjust data
	 */
	if (mrec->leaf.data_len && mrec->leaf.data_offset) {
		ndata = hammer_alloc_data(trans, mrec->leaf.data_len,
					  mrec->leaf.base.rec_type,
					  &ndata_offset, &data_buffer, &error);
		if (ndata == NULL)
			return(error);
		mrec->leaf.data_offset = ndata_offset;
		hammer_modify_buffer(trans, data_buffer, NULL, 0);
		error = copyin(udata, ndata, mrec->leaf.data_len);
		if (error == 0) {
			if (hammer_crc_test_leaf(ndata, &mrec->leaf) == 0) {
				kprintf("data crc mismatch on pipe\n");
				error = EINVAL;
			} else {
				error = hammer_mirror_localize_data(
							ndata, &mrec->leaf);
			}
		}
		hammer_modify_buffer_done(data_buffer);
	} else {
		mrec->leaf.data_offset = 0;
		error = 0;
		ndata = NULL;
	}
	if (error)
		goto failed;

	/*
	 * Do the insertion.  This can fail with a EDEADLK or EALREADY
	 */
	cursor->flags |= HAMMER_CURSOR_INSERT;
	error = hammer_btree_lookup(cursor);
	if (error != ENOENT) {
		if (error == 0)
			error = EALREADY;
		goto failed;
	}

	error = hammer_btree_insert(cursor, &mrec->leaf, &doprop);

	/*
	 * Cursor is left on the current element, we want to skip it now.
	 */
	cursor->flags |= HAMMER_CURSOR_ATEDISK;
	cursor->flags &= ~HAMMER_CURSOR_INSERT;

	/*
	 * Track a count of active inodes.
	 */
	if (error == 0 && mrec->leaf.base.delete_tid == 0 &&
	    mrec->leaf.base.obj_type == HAMMER_RECTYPE_INODE) {
		hammer_modify_volume_field(trans,
					   trans->rootvol,
					   vol0_stat_inodes);
		++trans->hmp->rootvol->ondisk->vol0_stat_inodes;
		hammer_modify_volume_done(trans->rootvol);
	}

	/*
	 * vol0_next_tid must track the highest TID stored in the filesystem.
	 * We do not need to generate undo for this update.
	 */
	high_tid = mrec->leaf.base.create_tid;
	if (high_tid < mrec->leaf.base.delete_tid)
		high_tid = mrec->leaf.base.delete_tid;
	if (trans->rootvol->ondisk->vol0_next_tid < high_tid) {
		hammer_modify_volume(trans, trans->rootvol, NULL, 0);
		trans->rootvol->ondisk->vol0_next_tid = high_tid;
		hammer_modify_volume_done(trans->rootvol);
	}

	if (error == 0 && doprop)
		hammer_btree_do_propagation(cursor, NULL, &mrec->leaf);

failed:
	/*
	 * Cleanup
	 */
	if (error && mrec->leaf.data_offset) {
		hammer_blockmap_free(cursor->trans,
				     mrec->leaf.data_offset,
				     mrec->leaf.data_len);
	}
	hammer_sync_unlock(trans);
	if (data_buffer)
		hammer_rel_buffer(data_buffer, 0);
	return(error);
}

/*
 * Localize the data payload.  Directory entries may need their
 * localization adjusted.
 *
 * PFS directory entries must be skipped entirely (return EALREADY).
 */
static
int
hammer_mirror_localize_data(hammer_data_ondisk_t data,
			    hammer_btree_leaf_elm_t leaf)
{
	u_int32_t localization;

	if (leaf->base.rec_type == HAMMER_RECTYPE_DIRENTRY) {
		if (data->entry.obj_id == HAMMER_OBJID_ROOT)
			return(EALREADY);
		localization = leaf->base.localization &
			       HAMMER_LOCALIZE_PSEUDOFS_MASK;
		if (data->entry.localization != localization) {
			data->entry.localization = localization;
			hammer_crc_set_leaf(data, leaf);
		}
	}
	return(0);
}

/*
 * Auto-detect the pseudofs.
 */
static
void
hammer_mirror_autodetect(struct hammer_ioc_pseudofs_rw *pfs, hammer_inode_t ip)
{
	if (pfs->pfs_id == -1)
		pfs->pfs_id = (int)(ip->obj_localization >> 16);
}

/*
 * Get mirroring/pseudo-fs information
 */
int
hammer_ioc_get_pseudofs(hammer_transaction_t trans, hammer_inode_t ip,
			struct hammer_ioc_pseudofs_rw *pfs)
{
	hammer_pseudofs_inmem_t pfsm;
	u_int32_t localization;
	int error;

	hammer_mirror_autodetect(pfs, ip);
	if (pfs->pfs_id < 0 || pfs->pfs_id >= HAMMER_MAX_PFS)
		return(EINVAL);
	localization = (u_int32_t)pfs->pfs_id << 16;
	pfs->bytes = sizeof(struct hammer_pseudofs_data);
	pfs->version = HAMMER_IOC_PSEUDOFS_VERSION;

	pfsm = hammer_load_pseudofs(trans, localization, &error);
	if (error) {
		hammer_rel_pseudofs(trans->hmp, pfsm);
		return(error);
	}

	/*
	 * If the PFS is a master the sync tid is set by normal operation
	 * rather then the mirroring code, and will always track the
	 * real HAMMER filesystem.
	 */
	if (pfsm->pfsd.master_id >= 0)
		pfsm->pfsd.sync_end_tid = trans->rootvol->ondisk->vol0_next_tid;

	/*
	 * Copy out to userland.
	 */
	error = 0;
	if (pfs->ondisk && error == 0)
		error = copyout(&pfsm->pfsd, pfs->ondisk, sizeof(pfsm->pfsd));
	hammer_rel_pseudofs(trans->hmp, pfsm);
	return(error);
}

/*
 * Set mirroring/pseudo-fs information
 */
int
hammer_ioc_set_pseudofs(hammer_transaction_t trans, hammer_inode_t ip,
			struct ucred *cred, struct hammer_ioc_pseudofs_rw *pfs)
{
	hammer_pseudofs_inmem_t pfsm;
	int error;
	u_int32_t localization;

	error = 0;
	hammer_mirror_autodetect(pfs, ip);
	if (pfs->pfs_id < 0 || pfs->pfs_id >= HAMMER_MAX_PFS)
		error = EINVAL;
	if (pfs->bytes != sizeof(pfsm->pfsd))
		error = EINVAL;
	if (pfs->version != HAMMER_IOC_PSEUDOFS_VERSION)
		error = EINVAL;
	if (error == 0 && pfs->ondisk) {
		/*
		 * Load the PFS so we can modify our in-core copy.
		 */
		localization = (u_int32_t)pfs->pfs_id << 16;
		pfsm = hammer_load_pseudofs(trans, localization, &error);
		error = copyin(pfs->ondisk, &pfsm->pfsd, sizeof(pfsm->pfsd));

		/*
		 * Save it back, create a root inode if we are in master
		 * mode and no root exists.
		 */
		if (error == 0)
			error = hammer_mkroot_pseudofs(trans, cred, pfsm);
		if (error == 0)
			error = hammer_save_pseudofs(trans, pfsm);
		hammer_rel_pseudofs(trans->hmp, pfsm);
	}
	return(error);
}

