/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdint.h>
#include <stdbool.h>

#include "knot/updates/changesets.h"
#include "libknot/db/db.h"
#include "libknot/dname.h"

/*!
 * \brief Journal structure.
 */
typedef struct {
	knot_db_t *db;               /*!< DB handler. */
	const knot_db_api_t *db_api; /*!< DB API backend. */
	char *path;                  /*!< Path to journal file. */
	size_t fslimit;              /*!< File size limit. */
} journal_t;

/*!
 * \brief Open journal.
 *
 * \param path     Journal file name.
 * \param fslimit  File size limit (0 for default limit).
 *
 * \retval new journal instance if successful.
 * \retval NULL on error.
 */
journal_t *journal_open(const char *path, size_t fslimit);

/*!
 * \brief Close journal file.
 *
 * \param journal  Journal to close.
 */
void journal_close(journal_t **journal);

/*!
 * \brief Load changesets from journal.
 *
 * \param journal    Journal to load from.
 * \param zone_name  Corresponding zone name.
 * \param dst        Store changesets here.
 * \param from       Start serial.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOENT when the lookup of the first entry fails.
 * \return < KNOT_EOK on other error.
 */
int journal_load_changesets(journal_t *journal, const knot_dname_t *zone_name,
                            list_t *dst, uint32_t from);

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
