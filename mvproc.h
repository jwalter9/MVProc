/*
   Copyright 2010 Jeff Walter

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef _MVPROC_H
#define _MVPROC_H

#define MAX_NEST 64

#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "time.h"
#include "math.h"
#include "sys/stat.h" 
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "util_md5.h"
#include "apr.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apreq.h"
#include "apreq_module.h"
#include "apreq2/apreq_module_apache2.h"

typedef unsigned long mvulong;


/*  DB typedefs  */
typedef enum { IN, INOUT, OUT } inout_t;

typedef struct db_param_t {
    char *name;
    inout_t in_or_out;
    struct db_param_t *next;
} db_param_t;

typedef struct {
    db_param_t *param;
    char *val;
} db_call_param;

typedef struct modmvproc_cache {
    char *procname;
    db_param_t *param_list;
    struct modmvproc_cache *next;
    size_t num_params;
} modmvproc_cache;

typedef enum {
    _BLOB,
    _STRING,
    _DOUBLE,
    _LONG,
    _DATETIME
} db_col_type;

typedef struct {
    char *val;
    mvulong size;
    db_col_type type;
} db_val_t;

typedef struct {
    char *name;
    db_val_t *vals;
} db_col_t;

typedef struct modmvproc_table {
    char *name;
    mvulong num_rows;
    mvulong num_fields;
    db_col_t *cols;
    struct modmvproc_table *next;
} modmvproc_table;


/*  Template typedefs  */
typedef enum {
    _NOTAG,
    _VALUE,
    _IF,
    _ELSIF,
    _ELSE,
    _ENDIF,
    _LOOP,
    _ENDLOOP,
    _INCLUDE,
    _SET
} tag_type;

typedef enum {
    _EQ,
    _NE,
    _GT,
    _GTE,
    _LT,
    _LTE,
    _NOTNULL,
    _NULL
} oper_t;

typedef enum {
    _SETVAL,
    _ADD,
    _SUBTRACT,
    _MULTIPLY,
    _DIVIDE,
    _MOD,
    _ALSO,
    _NOOP
} mvmath_t;

typedef struct {
    char *left;
    unsigned short cons_left;
    char *right;
    unsigned short cons_right;
    oper_t oper;
    db_col_type type;
} expression_t;

typedef struct cond_t {
    expression_t *exp;
    struct cond_t *deeper;
    struct cond_t *orc;
    struct cond_t *andc;
} cond_t;

typedef struct user_val_t {
    char *tag;
    unsigned short cons;
    db_col_type type;
    mvmath_t oper;
    struct user_val_t *deeper;
    struct user_val_t *next;
} user_val_t;

typedef struct template_segment_t {
    char *tag; /* NULL for first section of a template */
    char *follow_text;
    tag_type type;
    cond_t *ifs; /* NULL unless type _IF or _ELSIF */
    user_val_t *sets;
    struct template_segment_t *next;
} template_segment_t;

typedef struct template_cache_t {
    char *filename;
    char *file_content;
    template_segment_t *pieces;
    struct template_cache_t *next;
} template_cache_t;

typedef struct {
	char session;
	char *group;
	char *template_dir;
	modmvproc_cache *cache;
	template_cache_t *template_cache;
	void *pool;
} modmvproc_config;

typedef struct {
    char *table;
    mvulong cur_row;
    mvulong num_rows;
    template_segment_t *start_piece;
} fornest_tracker;

#endif
