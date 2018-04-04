/******************************************************************************/
/**
@file		osijoin.c
@author		Graeme Douglas
@brief		Implementation of the one-sided index join.
@see		For more information, reference @ref osijoin.h.
@details
@copyright	Copyright 2013 Graeme Douglas
@license	Licensed under the Apache License, Version 2.0 (the "License");
		you may not use this file except in compliance with the License.
		You may obtain a copy of the License at
			http://www.apache.org/licenses/LICENSE-2.0

@par
		Unless required by applicable law or agreed to in writing,
		software distributed under the License is distributed on an
		"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
		either express or implied. See the License for the specific
		language governing permissions and limitations under the
		License.
*/
/******************************************************************************/

#include "db_ops.h"
#include "../dbmacros.h"
#include "osijoin.h"

/* Initialize the operator. */
db_int init_osijoin(osijoin_t *jp, db_eet_t *ep, db_op_base_t *lchild,
		db_op_base_t *rchild, db_query_mm_t *mmp)
{
	// FIXME: This only works if expression passed in is already initialized.
	init_ntjoin((ntjoin_t*)jp, ep, lchild, rchild, mmp);
	return setup_osijoin(jp, mmp);
}

/* This for now assumes that we are only doing a=b join conditions, where a
   b are from different relations. */
db_int setup_osijoin(osijoin_t *jp, db_query_mm_t *mmp)
{	
	db_int8 rindexed = -1, lindexed = -1;
	db_eetnode_t *cursor = jp->tree->nodes;
	db_eetnode_attr_t *lattrp, *rattrp;
	db_uint8 count = 0, lcount = 0, rcount = 0;
	signed int lvalid;

	db_eetnode_attr_t *hold_attr = NULL;

	db_op_base_t *indexed, *unindexed;

	if (NULL == jp->tree || NULL == jp->tree->nodes)	return 0;
	
	// FIXME: See below.
	/* For now, we'll assume that things need to be indexed on a single attribute. */
	/* We also need to make the assumption that this condition only contains
	   stuff for this join specifically. */
	while (POINTERBYTEDIST(cursor, jp->tree->nodes) < jp->tree->size)
	{
		if (DB_EETNODE_ATTR == cursor->type)
		{	
			hold_attr = malloc(sizeof(db_eetnode_attr_t));
			memcpy(hold_attr, cursor, sizeof(db_eetnode_attr_t));
			if (1==(hold_attr->tuple_pos))
			{
				//rattrp = (db_eetnode_attr_t*)cursor;
				rattrp = hold_attr;
				rcount++;
				rindexed = findindexon((scan_t*)(jp->rchild), rattrp);
			}
			else if (0==(hold_attr->tuple_pos))
			{
				//lattrp = (db_eetnode_attr_t*)cursor;
				lattrp = hold_attr;
				lcount++;
				lindexed = findindexon((scan_t*)(jp->lchild), lattrp);
			}
			else
			{
				return 0;
			}
			free(hold_attr);
		}
		else if (DB_EETNODE_OP_EQ == cursor->type)
		{
			/* Do nothing, these are allowed. */	
		}
		else
			return 0;
		advanceeetnodepointer(&cursor, 1);
		count++;
	}
	
	if (3 != count || lcount > 1 || rcount > 1)
		return 0;
	
	jp->bitinfo = 1;
	if (rindexed < 0)
	{
		if (lindexed >= 0)
		{
			jp->indexon = (db_uint8)lindexed;
			indexed = jp->lchild;
			unindexed = jp->rchild;
			jp->bitinfo = 0;
			jp->uexpr = DB_QMM_BALLOC(mmp, sizeof(db_eet_t));
			jp->uexpr->size = sizeof(db_eetnode_attr_t);
			jp->uexpr->nodes = DB_QMM_BALLOC(mmp, sizeof(db_eetnode_attr_t));
			//*((db_eetnode_attr_t*)(jp->uexpr->nodes)) = *rattrp;
			memcpy(jp->uexpr->nodes, &rattrp, sizeof(db_eetnode_attr_t));
			//((db_eetnode_attr_t*)(jp->uexpr->nodes))->tuple_pos = 0;
			hold_attr = malloc(sizeof(db_eetnode_attr_t));
			memcpy(hold_attr, jp->uexpr->nodes, sizeof(db_eetnode_attr_t));
			hold_attr->tuple_pos = 0;
			memcpy(jp->uexpr->nodes, hold_attr, sizeof(db_eetnode_attr_t));
			free(hold_attr);
			
			/* If our new tuple will not fit in old one, create a new one. */
			if (
			    ((((jp->rchild->header->num_attr) / 8) + ((jp->rchild->header->num_attr) % 8)) >
			     (((jp->lchild->header->num_attr) / 8) + ((jp->lchild->header->num_attr) % 8))) ||
			    ((jp->rchild->header->tuple_size) > (jp->lchild->header->tuple_size))
			)
			{
				close_tuple(&(jp->ut), mmp);
				init_tuple(&(jp->ut), jp->rchild->header->num_attr, jp->rchild->header->tuple_size, mmp);
				next(jp->rchild, &(jp->ut), mmp);
			}
		}
		else
			return 0;
	}
	else
	{
		jp->indexon = (db_uint8)rindexed;
		indexed = jp->rchild;
		unindexed = jp->lchild;
		jp->uexpr = DB_QMM_BALLOC(mmp, sizeof(db_eet_t));
		jp->uexpr->size = sizeof(db_eetnode_attr_t);
		jp->uexpr->nodes = DB_QMM_BALLOC(mmp, sizeof(db_eetnode_attr_t));
		//*((db_eetnode_attr_t*)(jp->uexpr->nodes)) = *lattrp;
		memcpy(jp->uexpr->nodes, lattrp, sizeof(db_eetnode_attr_t));
	}
	
	rewind_dbop(unindexed, mmp);
	DB_OSIJOIN_UPDATE_UMORE(jp->bitinfo, next(unindexed, &(jp->ut), mmp));
	
	lvalid = scan_find((scan_t*)indexed,
			jp->indexon,
			jp->uexpr,
			&(jp->ut),
			unindexed->header,
			mmp);
	DB_OSIJOIN_UPDATE_IVALID(jp->bitinfo, lvalid);
	
	jp->base.type = DB_OSIJOIN;
	return 1;
}

/* Re-start the operator from the beginning. This assumes the operator has
 * been initialized. */
db_int rewind_osijoin(osijoin_t *jp, db_query_mm_t *mmp)
{	
	db_op_base_t *indexed, *unindexed;
	signed int lvalid;

	rewind_dbop(jp->lchild, mmp);
	rewind_dbop(jp->rchild, mmp);
	
	if (DB_OSIJOIN_RINDEXED(jp->bitinfo))
	{
		indexed   = jp->rchild;
		unindexed = jp->lchild;
	}
	else
	{
		indexed   = jp->lchild;
		unindexed = jp->rchild;
	}
	
	DB_OSIJOIN_UPDATE_UMORE(jp->bitinfo, next(unindexed, &(jp->ut), mmp));
	
	lvalid = scan_find((scan_t*)indexed,
			jp->indexon,
			jp->uexpr,
			&(jp->ut),
			unindexed->header,
			mmp);
	DB_OSIJOIN_UPDATE_IVALID(jp->bitinfo, lvalid);
	
	return 1;
}

db_int next_osijoin(osijoin_t *jp, db_tuple_t *next_tp, db_query_mm_t *mmp)
{
	/* Create necessary result variable. */
	db_int result = 0;
	db_op_base_t *indexed, *unindexed;
	db_tuple_t *it;
	signed int lvalid;
	db_int i;
	db_int j;
	
	db_tuple_t indexedtuple;
	db_int l_isnullsize;
	
	/* Build arrays to be passed to eet evaluation engine.
	   Left = 0, Right = 1. */
	relation_header_t *hpa[2];
	db_tuple_t *tpa[2];
	
	hpa[0] = jp->lchild->header;
	hpa[1] = jp->rchild->header;
	
	// TODO: Reduce memory footprint.
	it = &indexedtuple;
	
	if (DB_OSIJOIN_RINDEXED(jp->bitinfo))
	{
		unindexed = jp->lchild;
		indexed   = jp->rchild;
		tpa[0]    = &(jp->ut);
		tpa[1]    = it;
	}
	else
	{
		unindexed = jp->rchild;
		indexed   = jp->lchild;
		tpa[0]    = it;
		tpa[1]    = &(jp->ut);
	}
	
	init_tuple(it, indexed->header->tuple_size, indexed->header->num_attr, mmp);
	
	while (DB_OSIJOIN_UMORE(jp->bitinfo))
	{
		if (DB_OSIJOIN_IVALID(jp->bitinfo) && 1==next(indexed, it, mmp) && 1==evaluate_eet(jp->tree, &result, tpa, hpa, 0, mmp) && 1==result)
		{
		}
		else
		{
			DB_OSIJOIN_UPDATE_UMORE(jp->bitinfo, next(unindexed, &(jp->ut), mmp));
			lvalid = scan_find((scan_t*)indexed,
					jp->indexon,
					jp->uexpr,
					&(jp->ut),
					unindexed->header,
					mmp);
			DB_OSIJOIN_UPDATE_IVALID(jp->bitinfo, lvalid);
			continue;
		}
		
		/*** Do the join by combining the tuples
		 *   together. ***/
		/* Write out left tuples bytes into new tuple.
		 * */
		/* Write out left tuples isnull into new tuple.
		 * */
		
		l_isnullsize = (db_int)(hpa[0]->num_attr) % 8 > 0
			? ((db_int)(hpa[0]->num_attr) / 8) + 1
			: ((db_int)(hpa[0]->num_attr) / 8);
		
		copytuplebytes(next_tp, tpa[0], 0, 0, hpa[0]->tuple_size);
		
		copytupleisnull(next_tp, tpa[0], 0, 0, l_isnullsize);
		
		/* Write out right tuples bytes directly after
		 * left tuples bytes. */
		copytuplebytes(next_tp, tpa[1], hpa[0]->tuple_size, 0, hpa[1]->tuple_size);
		
		/* Write out right tuples isnull into new tuple.
		 * */
		j = (db_int)(hpa[0]->num_attr);
		for (i = 0; i < (db_int)(hpa[1]->num_attr); ++i)
		{
			/* If this bit is 0 ... */
			if (0 == (tpa[1]->isnull[i/8] & (1 << (i % 8))))
			{
				next_tp->isnull[j/8] &= ~(1 << (j % 8));
			}
			else
			{
				next_tp->isnull[j/8] |= (1 << (j % 8));
			}
			j++;
		}
		
		close_tuple(it, mmp);
		return 1;
	}
	
	close_tuple(it, mmp);
	return 0;
}

/* Close the selection operator. */
db_int close_osijoin(osijoin_t *jp, db_query_mm_t *mmp)
{
	close_tuple(&(jp->ut), mmp);
	
	/* Free all header properties that were allocated */
	DB_QMM_BFREE(mmp, jp->base.header->size_name);
	DB_QMM_BFREE(mmp, jp->base.header->names);
	DB_QMM_BFREE(mmp, jp->base.header->types);
	DB_QMM_BFREE(mmp, jp->base.header->offsets);
	DB_QMM_BFREE(mmp, jp->base.header->sizes);
	DB_QMM_BFREE(mmp, jp->uexpr->nodes);
	DB_QMM_BFREE(mmp, jp->uexpr);
	
	/* Free the header itself. */
	DB_QMM_BFREE(mmp, jp->base.header);
	
	/* For the time being, do nothing! */
	return 1;
}
