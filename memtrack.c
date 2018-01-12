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

/* $Id: memtrack.c 274405 2009-01-23 17:53:42Z tony2001 $ */

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
#include "zend_builtin_functions.h"
#include "ext/standard/php_var.h"
#include "zend_smart_str.h"

ZEND_DECLARE_MODULE_GLOBALS(memtrack)

#ifdef COMPILE_DL_MEMTRACK
ZEND_GET_MODULE(memtrack)
#endif

int memtrack_execute_initialized = 0;

void (*memtrack_old_execute_ex)(zend_execute_data *execute_data);
void memtrack_execute_ex(zend_execute_data *execute_data);
void (*memtrack_old_execute_internal)(zend_execute_data *current_execute_data, zval *return_value);
void memtrack_execute_internal(zend_execute_data *current_execute_data, zval *return_value);
static void (*mt_saved_on_timeout)(int seconds);
ZEND_DLEXPORT void memtrack_on_timeout(int seconds);

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

void mt_initialize_script_name()
{
	if (MEMTRACK_G(script_name)) {
		return;
	}

	if (HASH_OF(&PG(http_globals)[TRACK_VARS_SERVER]) != NULL) {
		zval *tmp;

		tmp = zend_hash_str_find_ind(HASH_OF(&PG(http_globals)[TRACK_VARS_SERVER]), "SCRIPT_NAME", sizeof("SCRIPT_NAME") - 1);
		if (tmp) {
			zend_string *str = zval_get_string(tmp);
			MEMTRACK_G(script_name) = estrndup(str->val, str->len);
			zend_string_release(str);
			return;
		}
	}
	MEMTRACK_G(script_name) = estrdup("<unknown>");
}

static char *mt_get_function_name(zend_execute_data *execute_data) /* {{{ */
{
	zend_string *str;
	zend_bool free_fname = 0;
	int class_name_len, fname_len;
	zend_class_entry *ce;
	char *class_name, *fname, *current_fname = NULL;
	const char *space;

	if (execute_data) {
		ce = execute_data->func->common.scope;
		class_name = ce ? ce->name->val : "";
		class_name_len = ce ? ce->name->len : 0;
	} else {
		class_name = (char *)get_active_class_name(&space);
		class_name_len = strlen(class_name);
	}

	if (class_name[0] == '\0') {
		if (execute_data && execute_data->func) {
			str = execute_data->func->common.function_name;
			if (str) {
				current_fname = str->val;
			}
		} else {
			current_fname = (char *)get_active_function_name(TSRMLS_C);
		}
	} else {
		if (execute_data && execute_data->func) {
			str = execute_data->func->common.function_name;
			if (str) {
				fname = str->val;
			}
		} else {
			fname = (char *)get_active_function_name(TSRMLS_C);
		}
		if (fname) {
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

		if (EG(current_execute_data) && EG(current_execute_data)->opline) {
			switch (EG(current_execute_data)->opline->extended_value) {
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

static char *mt_get_filename(zend_execute_data *execute_data, uint32_t *line) /* {{{ */
{
	*line = 0;
	while (execute_data && (!execute_data->func || !ZEND_USER_CODE(execute_data->func->type))) {
		execute_data = execute_data->prev_execute_data;
	}
	if (execute_data) {
		*line = execute_data->func->op_array.line_start;
		return ZSTR_VAL(execute_data->func->op_array.filename);
	} else {
		return "";
	}
}
/* }}} */

static void php_memtrack_parse_ignore_funcs(TSRMLS_D) /* {{{ */
{
	char *tmp, *for_free, *start = NULL;
	int start_len;
	zval dummy;

	ZVAL_NULL(&dummy);

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
						zend_hash_str_add(&MEMTRACK_G(ignore_funcs_hash), start, start_len, &dummy);
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
			zend_hash_str_add(&MEMTRACK_G(ignore_funcs_hash), start, start_len, &dummy);
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

static int php_memtrack_get_backtrace(zval *str_trace) /* {{{ */
{
	zval trace;
	smart_str buf = {0};

	if (EG(current_execute_data)) {
		zend_fetch_debug_backtrace(&trace, 0, DEBUG_BACKTRACE_IGNORE_ARGS, 0);
	} else {
		ZVAL_NULL(&trace);
	}

	if (!Z_ISUNDEF(MEMTRACK_G(data))) {
		Z_ADDREF_P(&MEMTRACK_G(data));
		add_assoc_zval(&trace, "memtrack_data", &MEMTRACK_G(data));
	}

	php_var_export_ex(&trace, 1, &buf);
	smart_str_0(&buf);

	ZVAL_STRINGL(str_trace, buf.s->val, buf.s->len);
	smart_str_free(&buf);

	zval_ptr_dtor(&trace);

	return SUCCESS;
}
/* }}} */

ZEND_DLEXPORT void memtrack_on_timeout(int seconds) /* {{{ */
{
	zval trace;
	char *buf;

	if (!MEMTRACK_G(enabled)) {
		mt_saved_on_timeout(seconds);
		return;
	}

	php_memtrack_get_backtrace(&trace);
	spprintf(&buf, 0, "[memtrack] [pid %d] Maximum execution time of %d second%s exceeded\nPHP backtrace:\n%s", getpid(), EG(timeout_seconds), EG(timeout_seconds) == 1 ? "" : "s", Z_STRVAL_P(&trace));

	zval_ptr_dtor(&trace);
	if (PG(error_log)) {
		php_log_err(buf);
	} else {
		zend_error(E_CORE_WARNING, "%s", buf);
	}
	mt_saved_on_timeout(seconds);
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

	mt_saved_on_timeout = zend_on_timeout;
	zend_on_timeout = memtrack_on_timeout;

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
		zend_execute_ex = memtrack_old_execute_ex;
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

	zend_hash_init(&MEMTRACK_G(ignore_funcs_hash), 16, NULL, ZVAL_PTR_DTOR, 0);

	if (!memtrack_execute_initialized) {
		memtrack_old_execute_ex = zend_execute_ex;
		zend_execute_ex = memtrack_execute_ex;

		if (zend_execute_internal) {
			memtrack_old_execute_internal = zend_execute_internal;
		} else {
			memtrack_old_execute_internal = execute_internal;
		}
		zend_execute_internal = memtrack_execute_internal;
		memtrack_execute_initialized = 1;
	}

	MEMTRACK_G(vm_warned) = 0;
	ZVAL_UNDEF(&MEMTRACK_G(data));

	php_memtrack_parse_ignore_funcs(TSRMLS_C);
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(memtrack)
{
	zval_ptr_dtor(&MEMTRACK_G(data));

	if (!MEMTRACK_G(enabled)) {
		return SUCCESS;
	}

	zend_hash_destroy(&MEMTRACK_G(ignore_funcs_hash));

	mt_initialize_script_name();

#ifdef PHP_MEMTRACK_HAVE_MALLINFO
	if (!MEMTRACK_G(vm_warned) && MEMTRACK_G(vm_limit) > 0) {
		int vmsize = memtrack_get_vm_size();

		if (vmsize > 0 && vmsize >= MEMTRACK_G(vm_limit)) {
			zend_error(E_CORE_WARNING, "[memtrack] [pid %d] [script: %s] virtual memory usage on shutdown: %d bytes", getpid(), MEMTRACK_G(script_name) ? MEMTRACK_G(script_name) : "unknown", vmsize);
		}
	}
#endif

	if (MEMTRACK_G(script_name)) {
		efree(MEMTRACK_G(script_name));
		MEMTRACK_G(script_name) = NULL;
	}

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(memtrack)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "memtrack support", "enabled");
	php_info_print_table_row(2, "Revision", "$Revision: 274405 $");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */

static PHP_FUNCTION(memtrack_data_set) /* {{{ */
{
	zval *data;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &data) != SUCCESS) {
		return;
	}

	if (!Z_ISUNDEF(MEMTRACK_G(data))) {
		zval_ptr_dtor(&MEMTRACK_G(data));
	}

	ZVAL_COPY_VALUE(&MEMTRACK_G(data), data);
	zval_copy_ctor(&MEMTRACK_G(data));

	RETURN_TRUE;
}
/* }}} */

static PHP_FUNCTION(memtrack_data_get) /* {{{ */
{
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "") != SUCCESS) {
		return;
	}

	if (!Z_ISUNDEF(MEMTRACK_G(data))) {
		RETURN_ZVAL(&MEMTRACK_G(data), 1, 0);
	}

	RETURN_FALSE;
}
/* }}} */

/* {{{ memtrack_functions[]
 */
zend_function_entry memtrack_functions[] = {
	PHP_FE(memtrack_data_set, NULL)
	PHP_FE(memtrack_data_get, NULL)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ memtrack_module_entry
 */
zend_module_entry memtrack_module_entry = {
	STANDARD_MODULE_HEADER,
	"memtrack",
	memtrack_functions,
	PHP_MINIT(memtrack),
	PHP_MSHUTDOWN(memtrack),
	PHP_RINIT(memtrack),
	PHP_RSHUTDOWN(memtrack),
	PHP_MINFO(memtrack),
	PHP_MEMTRACK_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

void memtrack_execute_ex(zend_execute_data *execute_data)
{
	if (MEMTRACK_G(soft_limit) <= 0 && MEMTRACK_G(hard_limit) <= 0) {
		memtrack_old_execute_ex(execute_data);
	} else {
		size_t memory_usage_start = 0, memory_usage_final = 0;
		size_t usage_diff = 0;

		memory_usage_start = zend_memory_usage(1);
		MEMTRACK_G(warnings) = 0;

		memtrack_old_execute_ex(execute_data);
		memory_usage_final = zend_memory_usage(1);

		if (MEMTRACK_G(warnings) && memory_usage_final > MEMTRACK_G(prev_memory_usage)) {
			usage_diff = memory_usage_final - MEMTRACK_G(prev_memory_usage);
		} else if (!MEMTRACK_G(warnings) && memory_usage_final > memory_usage_start) {
			usage_diff = memory_usage_final - memory_usage_start;
		}

		if (usage_diff >= MEMTRACK_G(soft_limit)) {
			char *fname, *lc_fname;
			const char *filename;
			uint32_t lineno;
			int fname_len;
			zend_execute_data *saved = EG(current_execute_data);
			EG(current_execute_data) = execute_data;

			filename = zend_get_executed_filename();
			lineno = zend_get_executed_lineno();

			fname = mt_get_function_name(execute_data);
			fname_len = strlen(fname);

			lc_fname = estrndup(fname, fname_len);
			zend_str_tolower(lc_fname, fname_len);

			if (usage_diff >= MEMTRACK_G(hard_limit) || zend_hash_str_exists(&MEMTRACK_G(ignore_funcs_hash), lc_fname, fname_len) == 0) {
				zval trace;
				char *buf;

				php_memtrack_get_backtrace(&trace);
				mt_initialize_script_name();
				spprintf(&buf, 0, "[memtrack] [pid %d] [script: %s] function %s() executed in %s on line %u allocated %zd bytes\nPHP backtrace:\n%s", getpid(), MEMTRACK_G(script_name), fname, filename, lineno, usage_diff, Z_STRVAL_P(&trace));

				zval_ptr_dtor(&trace);
				if (PG(error_log)) {
					php_log_err(buf);
				} else {
					zend_error(E_CORE_WARNING, "%s", buf);
				}
				efree(buf);
				MEMTRACK_G(warnings)++;
			}
			EG(current_execute_data) = saved;
			efree(fname);
			efree(lc_fname);
		}

		MEMTRACK_G(prev_memory_usage) = memory_usage_final;
	}

	if (!MEMTRACK_G(vm_warned) && MEMTRACK_G(vm_limit) > 0) {
		//int vmsize = memtrack_get_vm_size(); SLOOW
		size_t vmsize = zend_memory_usage(1);
		zend_execute_data *saved = EG(current_execute_data);
		EG(current_execute_data) = execute_data;

		if (vmsize > 0 && vmsize >= MEMTRACK_G(vm_limit)) {
			zval trace;
			php_memtrack_get_backtrace(&trace);
			mt_initialize_script_name();

			zend_error(E_CORE_WARNING, "[memtrack] [pid %d] [script: %s] virtual memory limit exceeded: vm_limit = %ldKb, actual value = %zdKb\nPHP backtrace:\n%s", getpid(), MEMTRACK_G(script_name), (long)(MEMTRACK_G(vm_limit)/1024), (size_t)(vmsize/1024), Z_STRVAL_P(&trace));
			MEMTRACK_G(vm_warned) = 1;
			zval_ptr_dtor(&trace);
		}
		EG(current_execute_data) = saved;
	}
}
/* }}} */

void memtrack_execute_internal(zend_execute_data *current_execute_data, zval *return_value)
{
	if (MEMTRACK_G(soft_limit) <= 0 && MEMTRACK_G(hard_limit) <= 0) {
		memtrack_old_execute_internal(current_execute_data, return_value);
	} else {
		size_t memory_usage_start = 0, memory_usage_final = 0;
		size_t usage_diff = 0;
		zend_execute_data *saved = EG(current_execute_data);
		EG(current_execute_data) = current_execute_data;

		memory_usage_start = zend_memory_usage(1);
		memtrack_old_execute_internal(current_execute_data, return_value);
		memory_usage_final = zend_memory_usage(1);

		if (memory_usage_final >= memory_usage_start) {
			usage_diff = memory_usage_final - memory_usage_start;
		}

		if (usage_diff >= MEMTRACK_G(soft_limit)) {
			char *lc_fname, *fname = mt_get_function_name(NULL);
			uint32_t lineno;
			char *filename;
			int fname_len;

			filename = mt_get_filename(current_execute_data, &lineno);
			fname_len = strlen(fname);

			lc_fname = estrndup(fname, fname_len);
			zend_str_tolower(lc_fname, fname_len);

			if (usage_diff >= MEMTRACK_G(hard_limit) || zend_hash_str_exists(&MEMTRACK_G(ignore_funcs_hash), lc_fname, fname_len) == 0) {
				zval trace;
				char *buf;

				php_memtrack_get_backtrace(&trace);
				spprintf(&buf, 0, "[memtrack] [pid %d] internal function %s() executed in %s on line %u allocated %zd bytes\nPHP backtrace:\n%s", getpid(), fname, filename, lineno, usage_diff, Z_STRVAL_P(&trace));
				zval_ptr_dtor(&trace);
				if (PG(error_log)) {
					php_log_err(buf);
				} else {
					zend_error(E_CORE_WARNING, "%s", buf);
				}
				efree(buf);
				MEMTRACK_G(warnings)++;
			}
			efree(fname);
			efree(lc_fname);
		}
		MEMTRACK_G(prev_memory_usage) = memory_usage_final;
		EG(current_execute_data) = saved;
	}

	if (!MEMTRACK_G(vm_warned) && MEMTRACK_G(vm_limit) > 0) {
		//int vmsize = memtrack_get_vm_size(); SLOOW
		size_t vmsize = zend_memory_usage(1);
		zend_execute_data *saved = EG(current_execute_data);
		EG(current_execute_data) = current_execute_data;

		if (vmsize > 0 && vmsize >= MEMTRACK_G(vm_limit)) {
			zval trace;
			php_memtrack_get_backtrace(&trace);
			mt_initialize_script_name();

			zend_error(E_CORE_WARNING, "[memtrack] [pid %d] [script: %s] virtual memory limit exceeded: vm_limit = %ldKb, actual value = %zdKb\nPHP backtrace:\n%s", getpid(), MEMTRACK_G(script_name), (long)(MEMTRACK_G(vm_limit)/1024), (size_t)(vmsize/1024), Z_STRVAL_P(&trace));
			MEMTRACK_G(vm_warned) = 1;
			zval_ptr_dtor(&trace);
		}
		EG(current_execute_data) = saved;
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
