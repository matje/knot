/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief Journal for storing transactions on permanent storage.
 *
 * We're using LMDB as the backend.
 *
 * \addtogroup server
 * @{
 */

#pragma once

#include <stdbool.h>

#include "knot/updates/changesets.h"
#include "libknot/dname.h"

/*!
 * \brief Journal structure.
 */
struct journal;
typedef struct journal journal_t;

/*!
 * \brief Allocate a new journal structure.
 *
 * \retval new journal instance if successful.
 * \retval NULL on error.
 */
journal_t *journal_new();

/*!
 * \brief Free a journal structure.
 *
 * \param journal  A journal structure to free.
 */
void journal_free(journal_t **journal);

/*!
 * \brief Open journal.
 *
 * \param journal    Journal struct to use.
 * \param path       Journal file name.
 * \param fslimit    File size limit (if < 1 MiB, 1 MiB is used).
 * \param zone_name  Name of the zone this journal belongs to.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EAGAIN when journal needs to be flushed, closed and reopen for
 *                     proper read-write access. This happens when opening
 *                     the journal with smaller mapsize than originally.
 * \retval KNOT_EBUSY when journal is already open.
 * \return < KNOT_EOK on other errors.
 */
int journal_open(journal_t *journal, const char *path, size_t fslimit,
                 const knot_dname_t *zone_name);

/*!
 * \brief Close journal file.
 *
 * \param journal  Journal to close.
 */
void journal_close(journal_t *journal);

/*!
 * \brief Load changesets from journal.
 *
 * \param journal  Journal to load from.
 * \param dst      Store changesets here.
 * \param from     Start serial.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOENT when the lookup of the first entry fails.
 * \return < KNOT_EOK on other error.
 */
int journal_load_changesets(journal_t *journal, list_t *dst, uint32_t from);

/*!
 * \brief Store changesets in journal.
 *
 * \param journal  Journal to store in.
 * \param src      Changesets to store.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBUSY when journal is full.
 * \return < KNOT_EOK on other errors.
 */
int journal_store_changesets(journal_t *journal, list_t *src);

/*!
 * \brief Store changesets in journal.
 *
 * \param journal  Journal to store in.
 * \param change   Changeset to store.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBUSY when journal is full.
 * \return < KNOT_EOK on other errors.
 */
int journal_store_changeset(journal_t *journal, changeset_t *change);

/*!
 * \brief Return number of stored items.
 *
 * \param journal  Journal.
 *
 * \return < KNOT_EOK on error, a count of stored items otherwise.
 */
int journal_count(journal_t *journal);

/*!
 * \brief Check if the journal file is used or not.
 *
 * \param path  Journal file.
 *
 * \return true or false
 */
bool journal_exists(const char *path);

/*! \brief Flush the journal, remove all data.
 *
 * \param journal  Journal to flush.
 *
 * \return KNOT_E*
 */
int journal_flush(journal_t *journal);

/*! @} */
