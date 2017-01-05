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

#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"
#include "contrib/mempattern.h"

#include <dirent.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#define MODULES_DIR (LIB_DIR "/knot/modules")

typedef struct {
	void *dl;
	static_module_t *info;
	yp_item_t *conf_scheme;
} dl_module_t;

static dl_module_t *MODULES = NULL;
static int n_modules = -1;

struct query_plan *query_plan_create(knot_mm_t *mm)
{
	struct query_plan *plan = mm_alloc(mm, sizeof(struct query_plan));
	if (plan == NULL) {
		return NULL;
	}

	plan->mm = mm;
	for (unsigned i = 0; i < QUERY_PLAN_STAGES; ++i) {
		init_list(&plan->stage[i]);
	}

	return plan;
}

void query_plan_free(struct query_plan *plan)
{
	if (plan == NULL) {
		return;
	}

	for (unsigned i = 0; i < QUERY_PLAN_STAGES; ++i) {
		struct query_step *step = NULL, *next = NULL;
		WALK_LIST_DELSAFE(step, next, plan->stage[i]) {
			mm_free(plan->mm, step);
		}
	}

	mm_free(plan->mm, plan);
}

static struct query_step *make_step(knot_mm_t *mm, qmodule_process_t process,
                                    void *ctx)
{
	struct query_step *step = mm_alloc(mm, sizeof(struct query_step));
	if (step == NULL) {
		return NULL;
	}

	memset(step, 0, sizeof(struct query_step));
	step->process = process;
	step->ctx = ctx;

	return step;
}

int query_plan_step(struct query_plan *plan, int stage, qmodule_process_t process,
                    void *ctx)
{
	struct query_step *step = make_step(plan->mm, process, ctx);
	if (step == NULL) {
		return KNOT_ENOMEM;
	}

	add_tail(&plan->stage[stage], &step->node);

	return KNOT_EOK;
}

static void unload_modules(void)
{
	for (int i=0; i < n_modules; ++i) {
		dlclose(MODULES[i].dl);
	}
	if (MODULES) {
		free(MODULES);
	}
}

static struct dirent *next_mod(DIR *dir)
{
	for (;;) {
		struct dirent *ent = readdir(dir);
		if (ent == NULL) {
			return NULL;
		}
		if (ent->d_name[0] == '.') {
			// Skip hidden files
			continue;
		}
		char *dot = strrchr(ent->d_name, '.');
		if (dot == NULL || strcmp(dot, ".so")) {
			// Skip files with the wrong file extension
			continue;
		}
		return ent;
	}
}

static void load_modules(void)
{
	if (n_modules != -1) {
		/* The modules are already loaded. */
		return;
	}

	n_modules = 0;
	atexit(unload_modules);

	DIR *dir = opendir(MODULES_DIR);
	if (dir == NULL) {
		log_info("Can't open modules directory %s", MODULES_DIR);
		return;
	}

	/* Count the modules. */
	int count = 0;
	for (struct dirent *ent = next_mod(dir); ent; ent = next_mod(dir)) {
		count ++;
	}

	if (count == 0) {
		/* There's nothing to load. */
		log_info("Loaded 0 modules");
		closedir(dir);
		return;
	}

	/* Allocate the modules array. */
	MODULES = calloc(count, sizeof(*MODULES));
	if (MODULES == NULL) {
		closedir(dir);
		log_error("failed to load modules: Out of memory");
		return;
	}

	/* Load the modules. */
	rewinddir(dir);
	int dirLen = strlen(MODULES_DIR);
	for (struct dirent *ent = next_mod(dir); ent; ent = next_mod(dir)) {
		if (n_modules == count) {
			/* This handles an unlikely race condition. */
			break;
		}

		dl_module_t *mod = &MODULES[n_modules];

		char *fn = malloc(dirLen + strlen(ent->d_name) + 2);
		if (fn == NULL) {
			log_info("Can't open module %s: Out of memory",
			         ent->d_name);
			continue;
		}
		sprintf(fn, "%s/%s", MODULES_DIR, ent->d_name);
		mod->dl = dlopen(fn, RTLD_NOW);
		free(fn);

		if (mod->dl == NULL) {
			log_info("Can't open module %s: %s",
			         ent->d_name, dlerror());
			continue;
		}

		mod->info = dlsym(mod->dl, "mod_info");
		if (mod->info == NULL) {
			log_info("Module %s missing symbol 'mod_info'",
			         ent->d_name);
			dlclose(mod->dl);
			continue;
		}

		mod->conf_scheme = dlsym(mod->dl, "mod_conf_scheme");
		if (mod->conf_scheme == NULL) {
			log_info("Module %s missing symbol 'mod_conf_scheme'",
			         ent->d_name);
			dlclose(mod->dl);
			continue;
		}

		n_modules ++;
	}

	log_info("Loaded %d modules", n_modules);

	closedir(dir);
}

static_module_t *find_module(const yp_name_t *name)
{
	/* Search for the module by name. */
	static_module_t *module = NULL;
	for (int i = 0; i < n_modules; ++i) {
		if (name[0] == MODULES[i].info->name[0] &&
		    memcmp(name + 1, MODULES[i].info->name + 1, name[0]) == 0) {
			module = MODULES[i].info;
			break;
		}
	}

	return module;
}

struct query_module *query_module_open(conf_t *config, conf_mod_id_t *mod_id,
                                       knot_mm_t *mm)
{
	if (config == NULL || mod_id == NULL) {
		return NULL;
	}

	/* Locate the module. */
	static_module_t *found = find_module(mod_id->name);
	if (found == NULL) {
		return NULL;
	}

	/* Create query module. */
	struct query_module *module = mm_alloc(mm, sizeof(struct query_module));
	if (module == NULL) {
		return NULL;
	}
	memset(module, 0, sizeof(struct query_module));

	module->mm = mm;
	module->config = config;
	module->id = mod_id;
	module->load = found->load;
	module->unload = found->unload;
	module->scope = found->scope;

	return module;
}

void query_module_close(struct query_module *module)
{
	if (module == NULL) {
		return;
	}

	conf_free_mod_id(module->id);
	mm_free(module->mm, module);
}

int query_module_count(void)
{
	load_modules();
	return n_modules;
}

void query_module_get_conf_schemes(yp_item_t *out_schemes)
{
	for (int i=0; i < n_modules; ++i) {
		out_schemes[i] = *MODULES[i].conf_scheme;
	}
}
