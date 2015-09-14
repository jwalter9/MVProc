/*
   Copyright 2010-2015 Jeff Walter

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
#include "unistd.h"
#include "sys/stat.h" 
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "util_md5.h"
#include "apr.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apreq.h"
#include "apreq_module.h"
#include "apreq2/apreq_module_apache2.h"
#include "apreq2/apreq_util.h"

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

typedef struct tpl_call_param {
	char *val;
	struct tpl_call_param *next;
} tpl_call_param;

typedef struct tpl_call_into {
	char *tablename;
	struct tpl_call_into *next;
} tpl_call_into;

typedef struct {
	char *procname;
	tpl_call_param *params;
	tpl_call_into *into;
} tpl_call_req;


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
    _TEMPLATE,
    _SET,
    _CALL
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

typedef enum {
    _XML_MIXED,
    _XML_NO_ATTR,
    _XML_EASY,
    _JSON_EASY,
    _JSON
} out_type;

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

typedef struct call_param_t {
	char *val;
	unsigned short cons;
	struct call_param_t *next;
} call_param_t;

typedef struct call_into_t {
	char *tablename;
	unsigned short cons;
	struct call_into_t *next;
} call_into_t;

typedef struct {
	char *procname;
	call_param_t *params;
	call_into_t *into;
} tpl_call_t;

typedef struct template_segment_t {
    char *tag; /* NULL for first section of a template */
    char *follow_text;
    tag_type type;
    cond_t *ifs; /* NULL unless type _IF or _ELSIF */
    user_val_t *sets;
    tpl_call_t *call;
    struct template_segment_t *next;
} template_segment_t;

typedef struct template_cache_t {
    char *filename;
    char *file_content;
    template_segment_t *pieces;
    struct template_cache_t *next;
} template_cache_t;

typedef struct user_var_t {
	char *varname;
	struct user_var_t *next;
} user_var_t;

typedef struct {
	char session;
	char *group;
	char *template_dir;
	modmvproc_cache *cache;
	template_cache_t *template_cache;
	void *pool;
	out_type output;
	char *error_tpl;
	char *default_layout;
	char *allow_setcontent;
	char allow_html_chars;
	char *upload_dir;
	char *default_proc;
	user_var_t *user_vars;
} modmvproc_config;

typedef struct {
    char *table;
    mvulong cur_row;
    mvulong num_rows;
    template_segment_t *start_piece;
} fornest_tracker;

static db_val_t *lookup(apr_pool_t *p, modmvproc_table *tables, 
                    const char *tableName, const char *colName, mvulong rowNum){
    if(strcmp(colName, "CURRENT_ROW") == 0){
        db_val_t *ret_val = (db_val_t *)apr_palloc(p, (sizeof(db_val_t)));
        if(ret_val == NULL) return NULL;
        ret_val->val = (char *)apr_palloc(p, 20 * sizeof(char));
        sprintf(ret_val->val, "%lu", rowNum);
        ret_val->type = _LONG;
        return ret_val;
    };
    if(strcmp(colName, "NUM_ROWS") == 0){
        db_val_t *ret_val = (db_val_t *)apr_palloc(p, (sizeof(db_val_t)));
        if(ret_val == NULL) return NULL;
        ret_val->val = (char *)apr_palloc(p, 20 * sizeof(char));
        sprintf(ret_val->val, "%lu", rowNum);
        ret_val->type = _LONG;
        while(tables != NULL){
            if(tables->name != NULL && strcmp(tables->name, tableName) == 0){
                sprintf(ret_val->val, "%lu", tables->num_rows);
                return ret_val;
            };
            tables = tables->next;
        };
        sprintf(ret_val->val, "%i", 0);
        return ret_val;
    };
    mvulong cind = 0;
    while(tables != NULL){
        if(tables->name != NULL && 
            strcmp(tables->name, tableName) == 0 && 
            rowNum < tables->num_rows)
            for(cind = 0; cind < tables->num_fields; cind++)
            if(strcmp(tables->cols[cind].name, colName) == 0)
                return &tables->cols[cind].vals[rowNum];
        tables = tables->next;
    };
    return NULL;
}

static void set_user_val(apr_pool_t *p, modmvproc_table *tables, 
                         char *tag, user_val_t *val){
    mvulong cind = 0;
    modmvproc_table *ntable;
    db_col_t *ncol;
    while(tables != NULL){
        if(strcmp(tables->name, "@") == 0){
            for(cind = 0; cind < tables->num_fields; cind++){
                if(strcmp(tables->cols[cind].name, tag) == 0){
                    tables->cols[cind].vals[0].val = val->tag;
                    tables->cols[cind].vals[0].type = val->type;
                    tables->cols[cind].vals[0].size = strlen(val->tag);
                    return;
                };
            };
            tables->num_fields++;
            ncol = (db_col_t *)apr_palloc(p, 
                tables->num_fields * sizeof(db_col_t));
            for(cind = 0; cind < tables->num_fields - 1; cind++){
                ncol[cind].name = tables->cols[cind].name;
                ncol[cind].vals = tables->cols[cind].vals;
            };
            ncol[cind].name = 
                (char *)apr_palloc(p, (strlen(tag) + 1) * sizeof(char));
            strcpy(ncol[cind].name, tag);
            ncol[cind].vals = (db_val_t *)apr_palloc(p, (sizeof(db_val_t)));
            if(ncol[cind].vals == NULL) return;
            ncol[cind].vals[0].type = val->type;
            ncol[cind].vals[0].val = val->tag;
            ncol[cind].vals[0].size = strlen(val->tag);
            tables->cols = ncol;
            return;
        };
        if(tables->next == NULL){
            ntable = (modmvproc_table *)apr_palloc(p, sizeof(modmvproc_table));
            if(ntable == NULL) return;
            ntable->name = (char *)apr_palloc(p, 2 * sizeof(char));
            if(ntable->name == NULL) return;
            strcpy(ntable->name, "@");
            ntable->num_rows = 1;
            ntable->num_fields = 1;
            ntable->cols = (db_col_t *)apr_palloc(p, sizeof(db_col_t));
            if(ntable->cols == NULL) return;
            ntable->cols[0].name = 
                (char *)apr_palloc(p, (strlen(tag) + 1) * sizeof(char));
            if(ntable->cols[0].name == NULL) return;
            strcpy(ntable->cols[0].name, tag);
            ntable->cols[0].vals = (db_val_t *)apr_palloc(p, (sizeof(db_val_t)));
            if(ntable->cols[0].vals == NULL) return;
            ntable->cols[0].vals[0].type = val->type;
            ntable->cols[0].vals[0].val = val->tag;
            ntable->cols[0].vals[0].size = strlen(val->tag);
            ntable->next = NULL;
            tables->next = ntable;
            return;
        };
        tables = tables->next;
    };
}


#endif
