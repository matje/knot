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
 * \brief Module for response-rate limiting
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "knot/nameserver/query_module.h"

/*! \brief Module scheme. */
#define C_MOD_RRL "\x07""mod-rrl"
extern const yp_item_t scheme_mod_rrl[];
int check_mod_rrl(conf_check_t *args);

/*! \brief Module interface. */
int rrl_load(struct query_plan *plan, struct query_module *self,
             const knot_dname_t *zone);
int rrl_unload(struct query_module *self);

/*! @} */
