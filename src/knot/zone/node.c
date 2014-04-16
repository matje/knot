/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <urcu.h>

#include "libknot/common.h"
#include "knot/zone/node.h"
#include "libknot/rrset.h"
#include "libknot/rdataset.h"
#include "libknot/rdata/rrsig.h"
#include "common/descriptor.h"
#include "common/debug.h"
#include "common/mempattern.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the given flag to node's flags.
 *
 * \param node Node to set the flag in.
 * \param flag Flag to set.
 */
static inline void knot_node_flags_set(knot_node_t *node, uint8_t flag)
{
	node->flags |= flag;
}

/*----------------------------------------------------------------------------*/

static void rr_data_clear(struct rr_data *data, mm_ctx_t *mm)
{
	knot_rdataset_clear(&data->rrs, mm);
	free(data->additional);
}

static int rr_data_from(const knot_rrset_t *rrset, struct rr_data *data, mm_ctx_t *mm)
{
	int ret = knot_rdataset_copy(&data->rrs, &rrset->rrs, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	data->type = rrset->type;
	data->additional = NULL;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_node_t *knot_node_new(const knot_dname_t *owner)
{
	knot_node_t *ret = malloc(sizeof(knot_node_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	memset(ret, 0, sizeof(*ret));

	if (owner) {
		ret->owner = knot_dname_copy(owner, NULL);
		if (ret->owner == NULL) {
			free(ret);
			return NULL;
		}
	}

	ret->flags = KNOT_NODE_FLAGS_NULL;

	return ret;
}

static int knot_node_add_rrset_no_merge(knot_node_t *node, const knot_rrset_t *rrset)
{
	if (node == NULL) {
		return KNOT_EINVAL;
	}

	const size_t nlen = (node->rrset_count + 1) * sizeof(struct rr_data);
	void *p = realloc(node->rrs, nlen);
	if (p == NULL) {
		return KNOT_ENOMEM;
	}
	node->rrs = p;
	int ret = rr_data_from(rrset, node->rrs + node->rrset_count, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}
	++node->rrset_count;

	return KNOT_EOK;
}

int knot_node_add_rrset(knot_node_t *node, const knot_rrset_t *rrset,  bool *ttl_err)
{
	if (node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == rrset->type) {
			struct rr_data *node_data = &node->rrs[i];

			/* Check if the added RR has the same TTL as the first
			 * RR in the RRSet.
			 */
			knot_rdata_t *first = knot_rdataset_at(&node_data->rrs, 0);
			uint32_t inserted_ttl = knot_rrset_rr_ttl(rrset, 0);
			if (ttl_err && rrset->type != KNOT_RRTYPE_RRSIG &&
			    inserted_ttl != knot_rdata_ttl(first)) {
				*ttl_err = true;
			}

			return knot_rdataset_merge(&node_data->rrs, &rrset->rrs, NULL);
		}
	}

	// New RRSet (with one RR)
	return knot_node_add_rrset_no_merge(node, rrset);
}

/*----------------------------------------------------------------------------*/

knot_rdataset_t *knot_node_rdataset(const knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return NULL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			return &node->rrs[i].rrs;
		}
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_node_create_rrset(const knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return NULL;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			knot_rrset_t rrset = knot_node_rrset_at(node, i);
			return knot_rrset_copy(&rrset, NULL);
		}
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

void knot_node_remove_rrset(knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return;
	}

	for (int i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			memmove(node->rrs + i, node->rrs + i + 1, (node->rrset_count - i - 1) * sizeof(struct rr_data));
			--node->rrset_count;
			return;
		}
	}

	return;
}

/*----------------------------------------------------------------------------*/

void knot_node_set_parent(knot_node_t *node, knot_node_t *parent)
{
	if (node == NULL || node->parent == parent) {
		return;
	}

	// decrease number of children of previous parent
	if (node->parent != NULL) {
		--node->parent->children;
	}
	// set the parent
	node->parent = parent;

	// increase the count of children of the new parent
	if (parent != NULL) {
		++parent->children;
	}
}

/*----------------------------------------------------------------------------*/

void knot_node_free_rrsets(knot_node_t *node)
{
	if (node == NULL) {
		return;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		rr_data_clear(&node->rrs[i], NULL);
	}
}

/*----------------------------------------------------------------------------*/

void knot_node_free(knot_node_t **node)
{
	if (node == NULL || *node == NULL) {
		return;
	}

	dbg_node_detail("Freeing node: %p\n", *node);

	if ((*node)->rrs != NULL) {
		dbg_node_detail("Freeing RRSets.\n");
		free((*node)->rrs);
		(*node)->rrs = NULL;
		(*node)->rrset_count = 0;
	}

	knot_dname_free(&(*node)->owner, NULL);

	free(*node);
	*node = NULL;

	dbg_node_detail("Done.\n");
}

/*----------------------------------------------------------------------------*/

int knot_node_shallow_copy(const knot_node_t *from, knot_node_t **to)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	// create new node
	*to = knot_node_new(from->owner);
	if (*to == NULL) {
		return KNOT_ENOMEM;
	}
	
	(*to)->flags = from->flags;

	// copy RRSets
	(*to)->rrset_count = from->rrset_count;
	size_t rrlen = sizeof(struct rr_data) * from->rrset_count;
	(*to)->rrs = malloc(rrlen);
	if ((*to)->rrs == NULL) {
		knot_node_free(to);
		return KNOT_ENOMEM;
	}
	memcpy((*to)->rrs, from->rrs, rrlen);
	for (uint16_t i = 0; i < from->rrset_count; ++i) {
		// Clear additionals in the copy.
		(*to)->rrs[i].additional = NULL;
	}

	return KNOT_EOK;
}

bool knot_node_rrtype_is_signed(const knot_node_t *node, uint16_t type)
{
	if (node == NULL) {
		return false;
	}

	const knot_rdataset_t *rrsigs = knot_node_rdataset(node, KNOT_RRTYPE_RRSIG);
	if (rrsigs == NULL) {
		return false;
	}

	uint16_t rrsigs_rdata_count = rrsigs->rr_count;
	for (uint16_t i = 0; i < rrsigs_rdata_count; ++i) {
		const uint16_t type_covered =
			knot_rrsig_type_covered(rrsigs, i);
		if (type_covered == type) {
			return true;
		}
	}

	return false;
}

bool knot_node_rrtype_exists(const knot_node_t *node, uint16_t type)
{
	return knot_node_rdataset(node, type) != NULL;
}
