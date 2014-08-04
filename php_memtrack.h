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

/* $Id: php_memtrack.h 274371 2009-01-23 14:02:12Z tony2001 $ */

#ifndef PHP_MEMTRACK_H
#define PHP_MEMTRACK_H

#define PHP_MEMTRACK_VERSION "0.2.0-dev"

extern zend_module_entry memtrack_module_entry;
#define phpext_memtrack_ptr &memtrack_module_entry

#if PHP_VERSION_ID < 50400

#define GET_OP2_TYPE(exec_data) exec_data->opline->op2.op_type
#define GET_OP2_NAME(exec_data) Z_LVAL(exec_data->opline->op2.u.constant)
#define ZEND_FETCH_DEBUG_BACKTRACE zend_fetch_debug_backtrace(trace, 0, 0 TSRMLS_CC)
#define PHP_OB_START_DEFAULT php_start_ob_buffer (NULL, 0, 1 TSRMLS_CC)
#define PHP_OB_GET_BUF(zval_buf) php_ob_get_buffer (zval_buf TSRMLS_CC)
#define PHP_OB_END_DISCARD php_end_ob_buffer(0, 0 TSRMLS_CC)

#else

#define GET_OP2_TYPE(exec_data) exec_data->opline->op2_type
#define GET_OP2_NAME(exec_data) exec_data->opline->op2.constant
#define ZEND_FETCH_DEBUG_BACKTRACE(trace) zend_fetch_debug_backtrace(trace, 0, 0, 0 TSRMLS_CC)
#define PHP_OB_START_DEFAULT php_output_start_default(TSRMLS_C)
#define PHP_OB_GET_BUF(zval_buf)  php_output_get_contents(zval_buf TSRMLS_CC)
#define PHP_OB_END_DISCARD php_output_discard(TSRMLS_CC)

#endif

#ifdef ZTS
#include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(memtrack)
	zend_bool enabled;
	long soft_limit;
	long hard_limit;
	long vm_limit;
	char *ignore_functions;
	HashTable ignore_funcs_hash;
	size_t prev_memory_usage;
	int warnings;
	int vm_warned;
	char *script_name;
ZEND_END_MODULE_GLOBALS(memtrack)

#ifdef ZTS
#define MEMTRACK_G(v) TSRMG(memtrack_globals_id, zend_memtrack_globals *, v)
#else
#define MEMTRACK_G(v) (memtrack_globals.v)
#endif

#endif	/* PHP_MEMTRACK_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
