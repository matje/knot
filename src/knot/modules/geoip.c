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

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/modules/geoip.h"

const yp_item_t scheme_mod_geoip[] = {
	{ C_ID,       YP_TSTR, YP_VNONE },
	{ C_GEOIP_DB, YP_TSTR, YP_VNONE },
	{ C_COMMENT,  YP_TSTR, YP_VNONE },
	{ NULL }
};

int geoip_check(conf_check_t *args)
{
	log_debug("%s", __func__);
	conf_val_t database = conf_rawid_get_txn(args->conf, args->txn,
	                                         C_MOD_GEOIP, C_GEOIP_DB,
	                                         args->previous->id,
	                                         args->previous->id_len);

	if (database.code != KNOT_EOK) {
		*args->err_str = "no database specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int geoip_load(struct query_plan *plan, struct query_module *self)
{
	log_debug("%s", __func__);
	return KNOT_EOK;
}

int geoip_unload(struct query_module *self)
{
	log_debug("%s", __func__);
	return KNOT_EOK;
}
