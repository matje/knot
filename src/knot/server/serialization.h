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
 * \brief API for changeset serialization.
 *
 * \addtogroup server
 * @{
 */

#pragma once

#include <stdint.h>

#include "knot/updates/changesets.h"

/*!
 * \brief Returns size of changeset in serialized form.
 *
 * \param[in] ch  Changeset whose size we want to compute.
 *
 * \return Size of the changeset.
 */
size_t changeset_serialized_size(const changeset_t *ch);

/*!
 * \brief Serializes one changeset into byte stream.
 *
 * \param[in]  ch    Changeset to serialize.
 * \param[out] dst   Output stream.
 * \param[in]  size  Output stream size.
 *
 * \return KNOT_E*
 */
int changeset_serialize(const changeset_t *ch, uint8_t *dst, size_t size);

/*!
 * \brief Deserializes one changeset from byte stream.
 *
 * \param[out] ch   Changeset to deserialize.
 * \param[in] src   Input stream.
 * \param[in] size  Input stream size.
 *
 * \return KNOT_E*
 */
int changeset_deserialize(changeset_t *ch, const uint8_t *src, size_t size);

/*! @} */
