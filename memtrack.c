/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2009 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Antony Dovgal <tony@daylessday.org>                          |
  +----------------------------------------------------------------------+
*/

/* $Id: memtrack.c 317388 2011-09-27 10:59:30Z tony2001 $ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_memtrack.h"

#include "zend.h"
#include "zend_API.h"
#include "zend_constants.h"
#include "zend_compile.h"
#include "zend_extensions.h"

ZEND_DECLARE_MODULE_GLOBALS(memtrack)

#ifdef COMPILE_DL_MEMTRACK
ZEND_GET_MODULE(memtrack)
#endif

int memtrack_execute_initialized = 0;

void (*memtrack_old_execute)(zend_op_array *op_array TSRMLS_DC);
void memtrack_execute(zend_op_array *op_array TSRMLS_DC);
void (*memtrack_old_execute_internal)(zend_execute_data *current_execute_data, int return_value_used TSRMLS_DC);
void memtrack_execute_internal(zend_execute_data *current_execute_data, int return_value_used TSRMLS_DC);

#ifdef PHP_MEMTRACK_HAVE_MALLINFO
# ifdef HAVE_MALLOC_H
#  include <malloc.h>
# endif
static int memtrack_get_vm_size(void) /* {{{ */
{
	struct mallinfo info;
	
	info = mallinfo();
	return info.arena + info.hblkhd;
}
/* }}} */
#endif

static char *mt_get_function_name(zend_op_array *op_array TSRMLS_DC) /* {{{ */
{
	char *current_fname = NULL;
	char *class_name, *fname;
	zend_bool free_fname = 0;
	int class_name_len, fname_len;
	zend_execute_data *exec_data = EG(current_execute_data);
	zend_class_entry *ce;
	char *space;
	
	if (op_array) {
		ce = ((zend_function *)op_array)->common.scope;
		class_name = ce ? ce->name : "";
	} else {
		class_name = get_active_class_name(&space TSRMLS_CC);
	}

	if (class_name[0] == '\0') {
		if (op_array) {
			current_fname = op_array->function_name;
		} else {
			current_fname = get_active_function_name(TSRMLS_C);
		}
	} else {
		if (op_array) {
			fname = op_array->function_name;
		} else {
			fname = get_active_function_name(TSRMLS_C);
		}
		if (fname) {
			class_name_len = strlen(class_name);
			fname_len = strlen(fname);

			current_fname = emalloc(class_name_len + 2 + fname_len + 1);
			free_fname = 1;

			memcpy(current_fname, class_name, class_name_len);
			memcpy(current_fname + class_name_len, "::", 2);
			memcpy(current_fname + class_name_len + 2, fname, fname_len);
			current_fname[class_name_len + 2 + fname_len] = '\0';
		}
	}

	if (!current_fname) {
		current_fname = "main";
	}

	if (!free_fname && !strcmp("main", current_fname)) {

		if (exec_data && exec_data->opline && exec_data->opline->op2.op_type == IS_UNUSED) {
			switch (Z_LVAL(exec_data->opline->op2.u.constant)) {
				case ZEND_REQUIRE_ONCE:
					current_fname = "require_once";
					break;
				case ZEND_INCLUDE:
					current_fname = "include";
					break;
				case ZEND_REQUIRE:
					current_fname = "require";
					break;
				case ZEND_INCLUDE_ONCE:
					current_fname = "include_once";
					break;
				case ZEND_EVAL:
					current_fname = "eval";
					break;
			}
		}
	}

	if (!free_fname) {
		return estrdup(current_fname);
	} else {
		return current_fname;
	}
}
/* }}} */

static void php_memtrack_parse_ignore_funcs(TSRMLS_D) /* {{{ */
{
	char *tmp, *for_free, *start = NULL;
	int dummy = 1, start_len;

	if (!MEMTRACK_G(ignore_functions) || MEMTRACK_G(ignore_functions)[0] == '\0') {
		return;
	}

	tmp = estrdup(MEMTRACK_G(ignore_functions));
	for_free = tmp;
	while(*tmp) {
		switch (*tmp) {
			case ' ':
			case ',':
				if (start) {
					*tmp = '\0';
					start_len = strlen(start);

					if (start_len) {
						zend_str_tolower(start, start_len);
						zend_hash_add(&MEMTRACK_G(ignore_funcs_hash), start, start_len + 1, (void *)&dummy, sizeof(int), NULL);
					}
					start = NULL;
				}
				break;
			default:
				if (!start) {
					start = tmp;
				}
				break;
		}
		tmp++;
	}
	if (start) {
		start_len = strlen(start);

		if (start_len) {
			zend_str_tolower(start, start_len);
			zend_hash_add(&MEMTRACK_G(ignore_funcs_hash), start, start_len + 1, (void *)&dummy, sizeof(int), NULL);
		}
	}
	efree(for_free);
}
/* }}} */

static void php_memtrack_init_globals(zend_memtrack_globals *memtrack_globals) /* {{{ */
{
	memset(memtrack_globals, 0, sizeof(zend_memtrack_globals));
}
/* }}} */

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("memtrack.enabled",         "0", PHP_INI_SYSTEM, OnUpdateBool, enabled, zend_memtrack_globals, memtrack_globals)
    STD_PHP_INI_ENTRY("memtrack.soft_limit",      "0", PHP_INI_ALL, OnUpdateLong, soft_limit, zend_memtrack_globals, memtrack_globals)
    STD_PHP_INI_ENTRY("memtrack.hard_limit",      "0", PHP_INI_ALL, OnUpdateLong, hard_limit, zend_memtrack_globals, memtrack_globals)
#ifdef PHP_MEMTRACK_HAVE_MALLINFO
    STD_PHP_INI_ENTRY("memtrack.vm_limit",        "0", PHP_INI_ALL, OnUpdateLong, vm_limit, zend_memtrack_globals, memtrack_globals)
#endif
    STD_PHP_INI_ENTRY("memtrack.ignore_functions", "", PHP_INI_SYSTEM, OnUpdateString, ignore_functions, zend_memtrack_globals, memtrack_globals)
PHP_INI_END()
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(memtrack)
{
	ZEND_INIT_MODULE_GLOBALS(memtrack, php_memtrack_init_globals, NULL);

	REGISTER_INI_ENTRIES();

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(memtrack)
{
	UNREGISTER_INI_ENTRIES();

	if (memtrack_execute_initialized) {
		zend_execute = memtrack_old_execute;
		zend_execute_internal = memtrack_old_execute_internal;
	}
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(memtrack)
{
	if (!MEMTRACK_G(enabled)) {
		return SUCCESS;
	}

	zend_hash_init(&MEMTRACK_G(ignore_funcs_hash), 16, NULL, NULL, 0);

	if (!memtrack_execute_initialized) {
		memtrack_old_execute = zend_execute;
		zend_execute = memtrack_execute;

		if (zend_execute_internal) {
			memtrack_old_execute_internal = zend_execute_internal;
		} else {
			memtrack_old_execute_internal = execute_internal;
		}
		zend_execute_internal = memtrack_execute_internal;
		memtrack_execute_initialized = 1;
	}

	php_memtrack_parse_ignore_funcs(TSRMLS_C);
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(memtrack)
{
	if (!MEMTRACK_G(enabled)) {
		return SUCCESS;
	}

	zend_hash_destroy(&MEMTRACK_G(ignore_funcs_hash));

#ifdef PHP_MEMTRACK_HAVE_MALLINFO
	if (MEMTRACK_G(vm_limit) > 0) {
		int vmsize = memtrack_get_vm_size();

		if (vmsize > 0 && vmsize >= MEMTRACK_G(vm_limit)) {
			zend_error(E_CORE_WARNING, "[memtrack] [pid %d] virtual memory usage on shutdown: %d bytes", getpid(), vmsize);
		}
	}
#endif
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(memtrack)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "memtrack support", "enabled");
	php_info_print_table_row(2, "Revision", "$Revision: 317388 $");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

/* {{{ memtrack_functions[]
 */
zend_function_entry memtrack_functions[] = {
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ memtrack_module_entry
 */
zend_module_entry memtrack_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"memtrack",
	memtrack_functions,
	PHP_MINIT(memtrack),
	PHP_MSHUTDOWN(memtrack),
	PHP_RINIT(memtrack),
	PHP_RSHUTDOWN(memtrack),
	PHP_MINFO(memtrack),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_MEMTRACK_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

void memtrack_execute(zend_op_array *op_array TSRMLS_DC) /* {{{ */
{
	if (MEMTRACK_G(soft_limit) <= 0 && MEMTRACK_G(hard_limit) <= 0) {
		memtrack_old_execute(op_array TSRMLS_CC);
	} else {
		size_t memory_usage_start = 0, memory_usage_final = 0;
		size_t usage_diff = 0;

		memory_usage_start = zend_memory_usage(1 TSRMLS_CC);
		MEMTRACK_G(warnings) = 0;

		memtrack_old_execute(op_array TSRMLS_CC);
		memory_usage_final = zend_memory_usage(1 TSRMLS_CC);

		if (MEMTRACK_G(warnings) && memory_usage_final > MEMTRACK_G(prev_memory_usage)) {
			usage_diff = memory_usage_final - MEMTRACK_G(prev_memory_usage);
		} else if (!MEMTRACK_G(warnings) && memory_usage_final > memory_usage_start) {
			usage_diff = memory_usage_final - memory_usage_start;
		}

		if (usage_diff >= MEMTRACK_G(soft_limit)) {
			char *fname, *lc_fname;
			char *filename = (EG(current_execute_data) && EG(current_execute_data)->op_array) ? EG(current_execute_data)->op_array->filename : "";
			int lineno = (EG(current_execute_data) && EG(current_execute_data)->opline) ? EG(current_execute_data)->opline->lineno : 0;
			int fname_len;

			fname = mt_get_function_name(op_array TSRMLS_CC);
			fname_len = strlen(fname);

			lc_fname = estrndup(fname, fname_len);
			zend_str_tolower(lc_fname, fname_len);

			if (usage_diff >= MEMTRACK_G(hard_limit) || zend_hash_exists(&MEMTRACK_G(ignore_funcs_hash), lc_fname, fname_len + 1) == 0) {
				zend_error(E_CORE_WARNING, "[memtrack] [pid %d] user function %s() executed in %s on line %d allocated %ld bytes", getpid(), fname, filename, lineno, usage_diff);
				MEMTRACK_G(warnings)++;
			}
			efree(fname);
			efree(lc_fname);
		}

		MEMTRACK_G(prev_memory_usage) = memory_usage_final;
	}
}
/* }}} */

void memtrack_execute_internal(zend_execute_data *current_execute_data, int return_value_used TSRMLS_DC) /* {{{ */
{
	if (MEMTRACK_G(soft_limit) <= 0 && MEMTRACK_G(hard_limit) <= 0) {
		memtrack_old_execute_internal(current_execute_data, return_value_used TSRMLS_CC);
	} else {
		size_t memory_usage_start = 0, memory_usage_final = 0;
		size_t usage_diff = 0;

		memory_usage_start = zend_memory_usage(1 TSRMLS_CC);
		memtrack_old_execute_internal(current_execute_data, return_value_used TSRMLS_CC);
		memory_usage_final = zend_memory_usage(1 TSRMLS_CC);

		if (memory_usage_final >= memory_usage_start) {
			usage_diff = memory_usage_final - memory_usage_start;
		}

		if (usage_diff >= MEMTRACK_G(soft_limit)) {
			char *lc_fname, *fname = mt_get_function_name(NULL TSRMLS_CC);
			int lineno = (current_execute_data && current_execute_data->opline) ? current_execute_data->opline->lineno : 0;
			char *filename = (current_execute_data && current_execute_data->op_array) ? current_execute_data->op_array->filename : "unknown";
			int fname_len;

			fname_len = strlen(fname);

			lc_fname = estrndup(fname, fname_len);
			zend_str_tolower(lc_fname, fname_len);

			if (usage_diff >= MEMTRACK_G(hard_limit) || zend_hash_exists(&MEMTRACK_G(ignore_funcs_hash), lc_fname, fname_len + 1) == 0) {
				zend_error(E_CORE_WARNING, "[memtrack] [pid %d] internal function %s() executed in %s on line %d allocated %ld bytes", getpid(), fname, filename, lineno, usage_diff);
				MEMTRACK_G(warnings)++;
			}
			efree(fname);
			efree(lc_fname);
		}
		MEMTRACK_G(prev_memory_usage) = memory_usage_final;
	}
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
