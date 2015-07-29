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

#ifndef _MVP_MYSQL
#define _MVP_MYSQL

#include "mvproc.h"
#include "mysql/mysql.h"
#include "apr_thread_mutex.h"

#define OUT_OF_MEMORY \
    { ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Out of memory: apr_palloc returned NULL"); \
      db_cleanup((mvpool_t *)cfg->pool, mysql); \
      return NULL; }

typedef struct{
    MYSQL *connections;
    char *locks;
    mvulong size;
    apr_thread_mutex_t *mutex;
}mvpool_t;
    
static void fill_proc_struct(apr_pool_t *p, const char *pname, 
                             const char *paramList, modmvproc_cache *cache_entry){
    cache_entry->procname = (char *)apr_palloc(p, (strlen(pname)+1) * sizeof(char));
    cache_entry->param_list = NULL;
    strcpy(cache_entry->procname, pname);
    db_param_t *param = NULL, *next_param = NULL;
    inout_t inout = IN;
    size_t pos = 0, len = strlen(paramList), i, num = 0;
    pos += strspn(paramList, " \t\r\n\0");
    while(pos < len){
        if(strncmp(&paramList[pos], "IN ", 3) == 0 || strncmp(&paramList[pos], "in ", 3) == 0){
            inout = IN;
            pos += 2;
        }else if(strncmp(&paramList[pos], "INOUT ", 6) == 0 || strncmp(&paramList[pos], "inout ", 6) == 0){
            inout = INOUT;
            pos += 5;
        }else if(strncmp(&paramList[pos], "OUT ", 4) == 0 || strncmp(&paramList[pos], "out ", 4) == 0){
            inout = OUT;
            pos += 3;
        }else{
            inout = IN;
        };
        pos += strspn(&paramList[pos], " \t\r\n\0");
        if(pos >= len) break;
        next_param = (db_param_t *)apr_palloc(p, sizeof(db_param_t));
        i = strcspn(&paramList[pos], " \t\r\n");
        if(pos + i >= len || i < 1) break;
        next_param->name = (char *)apr_palloc(p, (i + 1) * sizeof(char));
        strncpy(next_param->name, &paramList[pos], i);
        next_param->name[i] = '\0';
        pos += i;
        next_param->in_or_out = inout;
        next_param->next = NULL;
        num++;
        if(param != NULL){
            param->next = next_param;
        }else{
            cache_entry->param_list = next_param;
        };
        param = next_param;
        pos += strcspn(&paramList[pos], ",") + 1;
        if(pos >= len) break;
        pos += strspn(&paramList[pos], " \t\r\n");
        next_param = NULL;
    };
    cache_entry->num_params = num;
}

static const char *build_cache(apr_pool_t *p, modmvproc_config *cfg){
    MYSQL mysql;
    if(NULL == mysql_init(&mysql))
        return "Failed init";
    if(mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, cfg->group) != 0)
        return "Failed Option";
    if(mysql_real_connect(&mysql, NULL, NULL, NULL, NULL, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL)
        return mysql_error(&mysql);
    char query[1024];
    sprintf(query, "SELECT name, param_list FROM mysql.proc WHERE db='%s' AND type='PROCEDURE'",mysql.db);
    if(mysql_real_query(&mysql,query,strlen(query)) != 0) return mysql_error(&mysql);
    MYSQL_RES *result = mysql_store_result(&mysql);
    modmvproc_cache *ncache, *last = NULL;
    MYSQL_ROW row;
    while(NULL != (row = mysql_fetch_row(result))){
        ncache = (modmvproc_cache *)apr_palloc(p, sizeof(modmvproc_cache));
        ncache->next = NULL;
        fill_proc_struct(p, (char *)row[0], (char *)row[1], ncache);
        if(last != NULL) last->next = ncache;
        else cfg->cache = ncache;
        last = ncache;
    };
    mysql_free_result(result);
    mysql_close(&mysql);
    return NULL;
}

apr_status_t cleanup_connections(void *d){
    modmvproc_config *cfg = (modmvproc_config *)d;
    mvpool_t *pool = (mvpool_t*)cfg->pool;
    unsigned long iter;
    for(iter = 0; iter < pool->size; iter++){
        mysql_close(&pool->connections[iter]);
    };
    return APR_SUCCESS;
}

static const char *make_pool(apr_pool_t *p, modmvproc_config *cfg, unsigned long num){
    unsigned long iter;
    mvpool_t *newpool;
    newpool = (mvpool_t *)apr_palloc(p, sizeof(mvpool_t));
    if(newpool == NULL) return "Failed apr_palloc pool";
    newpool->connections = (MYSQL *)apr_palloc(p, num * sizeof(MYSQL));
    if(newpool->connections == NULL) return "Failed apr_palloc connections";
    newpool->locks = (char *)apr_palloc(p, num * sizeof(char));
    if(newpool->locks == NULL) return "Failed apr_palloc locks";
    newpool->size = num;
    if(APR_SUCCESS != apr_thread_mutex_create(&newpool->mutex,
        APR_THREAD_MUTEX_DEFAULT,p)) return "Failed to create mutex";
    for(iter = 0; iter < num; iter++){
        newpool->locks[iter] = 'o';
        mysql_init(&newpool->connections[iter]);
        if(&newpool->connections[iter] == NULL)
            return "Failed init";
        if(mysql_options(&newpool->connections[iter], 
            MYSQL_READ_DEFAULT_GROUP, cfg->group) != 0)
            return "Failed Option";
        if(mysql_real_connect(&newpool->connections[iter], 
            NULL, NULL, NULL, NULL, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL)
            return mysql_error(&newpool->connections[iter]);
    };
    cfg->pool = newpool;
    apr_pool_cleanup_register(p, cfg, cleanup_connections, cleanup_connections);
    return NULL;
}

static MYSQL *db_connect(modmvproc_config *cfg, request_rec *r){
    mvpool_t *thepool = (mvpool_t *)cfg->pool;
    MYSQL *mysql;
    if(thepool == NULL){
        mysql = apr_palloc(r->pool, sizeof(MYSQL));
        mysql_init(mysql);
        if(mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, cfg->group) != 0){
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MYSQL Options Failed");
            return NULL;
        };
        if(mysql_real_connect(mysql, 
            NULL, NULL, NULL, NULL, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL){
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MYSQL Connect Error: %s",
                mysql_error(mysql));
            return NULL;
        };
        return mysql;
    }else{
        unsigned long iter = thepool->size;
        while(1){
            if(APR_SUCCESS != apr_thread_mutex_lock(thepool->mutex)) return NULL;
            for(iter = 0; iter < thepool->size; iter++){
                if(thepool->locks[iter] == 'o'){
                    mysql = &thepool->connections[iter];
                    thepool->locks[iter] = 'l';
                    apr_thread_mutex_unlock(thepool->mutex);
                    if(mysql_ping(mysql) == 0) return mysql;
                    mysql_close(mysql);
                    mysql_init(mysql);
                    if(mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, cfg->group) != 0){
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MYSQL Options Failed");
                        return NULL;
                    };
                    if(mysql_real_connect(mysql, 
                        NULL, NULL, NULL, NULL, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL){
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MYSQL Connect Error: %s",
                            mysql_error(mysql));
                        return NULL;
                    };
                    return mysql;
                };
            };
            apr_thread_mutex_unlock(thepool->mutex);
            usleep(50);
        };
    };
}

static void db_cleanup(mvpool_t *pool, MYSQL *conn){
    if(pool == NULL){
        mysql_close(conn);
    }else{
        unsigned long iter = pool->size;
        if(APR_SUCCESS != apr_thread_mutex_lock(pool->mutex)) return;
        for(iter = 0; iter < pool->size; iter++){
            if(&pool->connections[iter] == conn){
                pool->locks[iter] = 'o';
                break;
            };
        };
        apr_thread_mutex_unlock(pool->mutex);
    };
}

static size_t escapeUserVar(MYSQL *m, const char *n, const char *p, char *q){
    if(p == NULL){
        sprintf(q, "SET @%s = ''; ", n);
    }else{
        char escaped[strlen(p) * 2 + 1];
        mysql_real_escape_string(m, escaped, p, strlen(p));
        sprintf(q, "SET @%s = '%s'; ", n, escaped);
    };
    return strlen(q);
}

static modmvproc_table *dbError(modmvproc_config *cfg, request_rec *r, 
                                MYSQL *mysql){
    const char *err = mysql_error(mysql);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MYSQL Error: %s", err);

    modmvproc_table *ret = 
    (modmvproc_table *)apr_palloc(r->pool, sizeof(modmvproc_table));
    if(ret == NULL) OUT_OF_MEMORY;
    ret->next = NULL;
    ret->name = (char *)apr_palloc(r->pool, 7 * sizeof(char));
    if(ret->name == NULL) OUT_OF_MEMORY;
    strcpy(ret->name, "status");
    ret->num_rows = 1;
    ret->num_fields = 1;
    ret->cols = (db_col_t *)apr_palloc(r->pool, sizeof(db_col_t));
    if(ret->cols == NULL) OUT_OF_MEMORY;
    ret->cols[0].name = (char *)apr_palloc(r->pool, 7 * sizeof(char));
    if(ret->cols[0].name == NULL) OUT_OF_MEMORY;
    strcpy(ret->cols[0].name, "error");
    ret->cols[0].vals = (db_val_t *)apr_palloc(r->pool, sizeof(db_val_t));
    if(ret->cols[0].vals == NULL) OUT_OF_MEMORY;
    ret->cols[0].vals[0].size = strlen(err);
    ret->cols[0].vals[0].val = 
        (char *)apr_palloc(r->pool, (ret->cols[0].vals[0].size + 1) * sizeof(char));
    if(ret->cols[0].vals[0].val == NULL) OUT_OF_MEMORY;
    strcpy(ret->cols[0].vals[0].val, err);
    ret->cols[0].vals[0].type = _BLOB;

    if(cfg->template_dir != NULL && cfg->error_tpl != NULL){
        ret->next =
        (modmvproc_table *)apr_palloc(r->pool, sizeof(modmvproc_table));
        if(ret->next == NULL) OUT_OF_MEMORY;
        ret->next->next = NULL;
        ret->next->name = (char *)apr_palloc(r->pool, 9 * sizeof(char));
        if(ret->next->name == NULL) OUT_OF_MEMORY;
        strcpy(ret->next->name, "PROC_OUT");
        ret->next->num_rows = 1;
        ret->next->num_fields = 1;
        ret->next->cols = (db_col_t *)apr_palloc(r->pool, sizeof(db_col_t));
        if(ret->next->cols == NULL) OUT_OF_MEMORY;
        ret->next->cols[0].name = 
            (char *)apr_palloc(r->pool, 13 * sizeof(char));
        if(ret->next->cols[0].name == NULL) OUT_OF_MEMORY;
        strcpy(ret->next->cols[0].name, "mvp_template");
        ret->next->cols[0].vals = 
            (db_val_t *)apr_palloc(r->pool, sizeof(db_val_t));
        if(ret->next->cols[0].vals == NULL) OUT_OF_MEMORY;
        ret->next->cols[0].vals[0].size = strlen(cfg->error_tpl);
        ret->next->cols[0].vals[0].val = 
            (char *)apr_palloc(r->pool, 
                (ret->next->cols[0].vals[0].size + 1) * sizeof(char));
        if(ret->next->cols[0].vals[0].val == NULL) OUT_OF_MEMORY;
        strcpy(ret->next->cols[0].vals[0].val, cfg->error_tpl);
        ret->next->cols[0].vals[0].type = _BLOB;
    };

    db_cleanup((mvpool_t *)cfg->pool, mysql);
    return ret;
}

static modmvproc_table *getDBResult(modmvproc_config *cfg, request_rec *r,
                                    apreq_handle_t *apreq, 
                                    const char *session_id, int *errback){

    MYSQL *mysql = db_connect(cfg, r);
    if(mysql == NULL) return NULL;
	modmvproc_cache *cache_entry = NULL;
	size_t qsize = 0, pos = 0;
    char *escaped;
    char *procname = (char *)apr_palloc(r->pool, strlen(r->uri) * 2 + 1);
    char uploaded[1024];
    char tmpfile[1024];
    char *upload_ext;
    /* first char of uri will be a '/' */
    mysql_real_escape_string(mysql, procname, r->uri + 1, strlen(r->uri) - 1); 
    MYSQL_RES *result;
    MYSQL_ROW row;

    const apreq_param_t *parsed_param;
    apr_file_t *fptr;
    apr_off_t *wlen = (apr_off_t *)apr_palloc(r->pool, sizeof(apr_off_t));
    if(wlen == NULL) OUT_OF_MEMORY;
    apr_status_t fstat;
    db_param_t *param;
    mvulong parm_ind = 0;

    if(cfg->cache != NULL){
        cache_entry = cfg->cache;
        while(cache_entry != NULL){
            if(strcmp(cache_entry->procname,procname) == 0) break;
            cache_entry = cache_entry->next;
        };
        if(cache_entry == NULL){
            if(cfg->default_proc == NULL){
              	procname = (char *)apr_palloc(r->pool, 8);
               	strcpy(procname, "landing");
            }else{
               	procname = (char *)apr_palloc(r->pool, 
               		strlen(cfg->default_proc) + 1);
               	strcpy(procname, cfg->default_proc);
            };
            cache_entry = cfg->cache;
            while(cache_entry != NULL){
               	if(strcmp(cache_entry->procname,procname) == 0) break;
               	cache_entry = cache_entry->next;
            };
            if(cache_entry == NULL){
            	db_cleanup((mvpool_t *)cfg->pool, mysql);
            	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
    	            "Request for unknown content: %s", procname);
            	*errback = DECLINED;
            	return NULL;
            };
        };
    }else{
        qsize = 85 + strlen(mysql->db) + strlen(procname);
        char *proc_query = apr_palloc(r->pool, qsize * sizeof(char));
        sprintf(proc_query, "SELECT name, param_list FROM mysql.proc WHERE db='%s' AND type='PROCEDURE' AND name='%s'",
            mysql->db, procname);
        if(mysql_real_query(mysql,proc_query,strlen(proc_query)) != 0){
            return dbError(cfg, r, mysql);
        };
        result = mysql_store_result(mysql);
        if(mysql_num_rows(result) < 1){
            /* no proc by that name? use default_proc or 'landing' */
            mysql_free_result(result);
            if(cfg->default_proc == NULL){
                procname = (char *)apr_palloc(r->pool, 8);
                strcpy(procname, "landing");
            }else{
                procname = (char *)apr_palloc(r->pool, strlen(cfg->default_proc) + 1);
                strcpy(procname, cfg->default_proc);
            };
            qsize = 85 + strlen(mysql->db) + strlen(procname);
            proc_query = apr_palloc(r->pool, qsize * sizeof(char));
            sprintf(proc_query, "SELECT name, param_list FROM mysql.proc WHERE db='%s' AND type='PROCEDURE' AND name='%s'",
                mysql->db, procname);
            if(mysql_real_query(mysql,proc_query,strlen(proc_query)) != 0){
                return dbError(cfg, r, mysql);
            };
            result = mysql_store_result(mysql);
            if(mysql_num_rows(result) < 1){
                mysql_free_result(result);
                db_cleanup((mvpool_t *)cfg->pool, mysql);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                    "Request for unknown content: %s", procname);
                *errback = DECLINED;
                return NULL;
            };
        };
        row = mysql_fetch_row(result);
        if(row == NULL){
            return dbError(cfg, r, mysql);
        };
        cache_entry = (modmvproc_cache *)apr_palloc(r->pool, (sizeof(modmvproc_cache)));
        if(cache_entry == NULL) OUT_OF_MEMORY;
        fill_proc_struct(r->pool, (char *)row[0], (char *)row[1], cache_entry);
    };

    /* large starting size for headroom and changes */
    qsize = 1024 + strlen(procname) + (
        strlen(session_id) * 2 + 
        strlen(r->server->server_hostname) * 2 +
        strlen(r->method) * 2 +
        strlen(r->unparsed_uri) * 2 +
        strlen(r->the_request) * 2 +
        strlen(r->useragent_ip)
        ) * 2;

    /* let's get ALL the headers for @mvp_headers */
    const apr_array_header_t *hfields;
    int i;
    size_t header_size = 0;
    size_t hpos = 0;
    apr_table_entry_t *e = 0;
    hfields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) hfields->elts;
    for(i = 0; i < hfields->nelts; i++) {
        header_size += (strlen(e[i].key) + strlen(e[i].val) + 3);
    };
    header_size++;
    qsize += header_size * 2 + 1;
    char all_headers[header_size];
    e = (apr_table_entry_t *) hfields->elts;
    for(i = 0; i < hfields->nelts; i++) {
        sprintf(&all_headers[hpos], "%s=%s; ", e[i].key, e[i].val);
        hpos += (strlen(e[i].key) + strlen(e[i].val) + 3);
    };

    parm_ind = 0;
    param = cache_entry->param_list;
    db_call_param inparms[cache_entry->num_params];
    while(param != NULL){
        uploaded[0] = '\0';
        parsed_param = apreq_param(apreq,param->name);
        if(parsed_param == NULL){
            inparms[parm_ind].val = NULL;
        }else{
            if(parsed_param->upload != NULL){
                strcpy(uploaded, cfg->upload_dir);
                pos = strlen(cfg->upload_dir);
                strcpy(&uploaded[pos], "/XXXXXX");
                fstat = apr_file_mktemp(&fptr, uploaded, APR_FOPEN_WRITE | APR_FOPEN_CREATE, r->pool);
                if(fstat == APR_SUCCESS){
                    fstat = apreq_brigade_fwrite(fptr, wlen, parsed_param->upload);
                    apr_file_close(fptr);
                };
                if(fstat == APR_SUCCESS){
                    fstat = apr_file_perms_set(uploaded, APR_OS_DEFAULT);
                    if(fstat == APR_INCOMPLETE || fstat == APR_ENOTIMPL) fstat = APR_SUCCESS;
                };
                upload_ext = strrchr(parsed_param->v.data, '.');
                if(fstat == APR_SUCCESS){
                    if(upload_ext != NULL && strlen(upload_ext) < 9){
                        strcpy(tmpfile, uploaded);
                        strcat(uploaded, upload_ext);
                        fstat = apr_file_rename(tmpfile, uploaded, r->pool);
                    };
                };
                if(fstat == APR_SUCCESS){
                    escaped = (char *)apr_palloc(r->pool, (strlen(uploaded) * 2 + 1) * sizeof(char));
                    if(escaped == NULL) OUT_OF_MEMORY;
                    mysql_real_escape_string(mysql, escaped, uploaded, strlen(uploaded));
                }else{
                    escaped = (char *)apr_palloc(r->pool, 256 * sizeof(char));
                    if(escaped == NULL) OUT_OF_MEMORY;
                    escaped = apr_strerror(fstat, escaped, 255);
                };
            }else{
                escaped = (char *)apr_palloc(r->pool, (strlen(parsed_param->v.data) * 2 + 1) * sizeof(char));
                if(escaped == NULL) OUT_OF_MEMORY;
                mysql_real_escape_string(mysql, escaped, parsed_param->v.data, strlen(parsed_param->v.data));
            };
            inparms[parm_ind].val = escaped;
        };
        switch(param->in_or_out){
        case IN:
            if(inparms[parm_ind].val == NULL){
                qsize += 6;
            }else{
                qsize += strlen(inparms[parm_ind].val) + 4;
            };
            break;
        case INOUT:
            if(inparms[parm_ind].val == NULL){
                qsize += strlen(param->name) * 2 + 19;
            }else{
                qsize += strlen(param->name) * 2 + strlen(inparms[parm_ind].val) + 17;
            };
            break;
        case OUT:
            qsize += strlen(param->name) * 2 + 17;
            break;
        default:
            break;
        };
        inparms[parm_ind].param = param;
        parm_ind++;
        param = param->next;
    };
    
    user_var_t *uvar = cfg->user_vars;
    while(uvar != NULL){
    	    qsize += strlen(uvar->varname) * 2 + 21;
    	    uvar = uvar->next;
    };
    
    pos = 0;
    char query[qsize];
    for(parm_ind = 0; parm_ind < cache_entry->num_params; parm_ind++){
        switch(inparms[parm_ind].param->in_or_out){
        case INOUT:
            if(inparms[parm_ind].val == NULL){
                sprintf(&query[pos],"SET @%s = NULL; ", inparms[parm_ind].param->name);
            }else{
                sprintf(&query[pos],"SET @%s = '%s'; ",
                    inparms[parm_ind].param->name,inparms[parm_ind].val);
            };
            pos = strlen(query);
            break;
        case OUT:
            sprintf(&query[pos],"SET @%s = ''; ",inparms[parm_ind].param->name);
            pos = strlen(query);
            break;
        default:
            break;
        };
    };
    
    if(cfg->session == 'Y' || cfg->session == 'y')
        pos += escapeUserVar(mysql, "mvp_session", session_id, &query[pos]);
    if(cfg->template_dir != NULL && strlen(cfg->template_dir) > 0){
        pos += escapeUserVar(mysql, "mvp_template", procname, &query[pos]);
        pos += escapeUserVar(mysql, "mvp_layout", cfg->default_layout, &query[pos]);
    };
    if(cfg->allow_setcontent != NULL)
        pos += escapeUserVar(mysql, "mvp_content_type", "", &query[pos]);
    pos += escapeUserVar(mysql, "mvp_servername", r->server->server_hostname, &query[pos]);
    pos += escapeUserVar(mysql, "mvp_requestmethod", r->method, &query[pos]);
    pos += escapeUserVar(mysql, "mvp_uri", r->unparsed_uri, &query[pos]);
    pos += escapeUserVar(mysql, "mvp_headers", all_headers, &query[pos]);
    pos += escapeUserVar(mysql, "mvp_remoteip", r->useragent_ip, &query[pos]);
    uvar = cfg->user_vars;
    while(uvar != NULL){
    	pos += escapeUserVar(mysql, uvar->varname, NULL, &query[pos]);
    	uvar = uvar->next;
    };
    
    sprintf(&query[pos], "CALL %s(",cache_entry->procname);
    pos = strlen(query);
    param = cache_entry->param_list;
    for(parm_ind = 0; parm_ind < cache_entry->num_params; parm_ind++){
        switch(inparms[parm_ind].param->in_or_out){
        case IN:
            if(inparms[parm_ind].val == NULL){
                strcpy(&query[pos], "NULL");
            }else{
                sprintf(&query[pos],"'%s'", inparms[parm_ind].val);
            };
            pos = strlen(query);
            break;
        case INOUT:
        case OUT:
            sprintf(&query[pos],"@%s",inparms[parm_ind].param->name);
            pos = strlen(query);
            break;
        };
        if(inparms[parm_ind].param->next != NULL){
            query[pos] = ',';
            pos++;
        };
    };
    sprintf(&query[pos],");");
    pos += 2;

    qsize = 0;
    for(parm_ind = 0; parm_ind < cache_entry->num_params; parm_ind++){
        switch(inparms[parm_ind].param->in_or_out){
        case INOUT:
        case OUT:
            sprintf(&query[pos],"%s@%s", qsize > 0 ? ", " : " SELECT ",
                inparms[parm_ind].param->name);
            pos = strlen(query);
            qsize++;
            break;
        default:
            break;
        };
    };

    if(cfg->session == 'Y' || cfg->session == 'y'){
        sprintf(&query[pos],"%s@%s", qsize > 0 ? ", ":" SELECT ","mvp_session");
        pos = strlen(query);
        qsize++;
    };

    if(cfg->template_dir != NULL && strlen(cfg->template_dir) > 0){
        sprintf(&query[pos],"%s@%s, @%s, @%s",qsize > 0 ? ", ":" SELECT ",
        	"mvp_template","mvp_layout","mvp_servername");
        pos = strlen(query);
        qsize += 3;
    };

    if(cfg->allow_setcontent != NULL){
        sprintf(&query[pos],"%s@%s",qsize > 0 ? ", ":" SELECT ","mvp_content_type");
        pos = strlen(query);
        qsize++;
    };

    uvar = cfg->user_vars;
    while(uvar != NULL){
        sprintf(&query[pos],"%s@%s",qsize > 0 ? ", ":" SELECT ",uvar->varname);
        pos = strlen(query);
        qsize++;
        uvar = uvar->next;
    };
    
    if(qsize > 0) sprintf(&query[pos],";");
    
    if(mysql_real_query(mysql,query,strlen(query)) != 0){
        return dbError(cfg, r, mysql);
    };

    int status = 0;
    mvulong f, ro, c, *lens;
    db_col_type *coltypes;
    MYSQL_FIELD *fields;
    
    modmvproc_table *next = 
    (modmvproc_table *)apr_palloc(r->pool, sizeof(modmvproc_table));
    if(next == NULL) OUT_OF_MEMORY;
    next->next = NULL;
    next->name = NULL;
    modmvproc_table *tables = next;
    modmvproc_table *last = NULL;
    
    do{
        result = mysql_store_result(mysql);
        if(result){
            next->num_rows = mysql_num_rows(result);
            if(next->num_rows < 1)continue;
            next->num_fields = mysql_num_fields(result);
            next->cols = (db_col_t *)apr_palloc(r->pool, 
                next->num_fields * sizeof(db_col_t));
            if(next->cols == NULL) OUT_OF_MEMORY;
            coltypes = (db_col_type *)apr_palloc(r->pool,
                next->num_fields * sizeof(db_col_type));
            for(c = 0; c < next->num_fields; c++)
                next->cols[c].name = NULL;

            fields = mysql_fetch_fields(result);
            next->name = NULL;
            for(f = 0; f < next->num_fields; f++){
                switch(fields[f].type){
                case MYSQL_TYPE_BLOB:
                    coltypes[f] = _BLOB;
                    break;
                case MYSQL_TYPE_BIT:
                case MYSQL_TYPE_TINY:
                case MYSQL_TYPE_SHORT:
                case MYSQL_TYPE_LONG:
                case MYSQL_TYPE_INT24:
                case MYSQL_TYPE_LONGLONG:
                    coltypes[f] = _LONG;
                    break;
                case MYSQL_TYPE_DECIMAL:
                case MYSQL_TYPE_NEWDECIMAL:
                case MYSQL_TYPE_FLOAT:
                case MYSQL_TYPE_DOUBLE:
                    coltypes[f] = _DOUBLE;
                    break;
                default:
                    coltypes[f] = _STRING;
                    break;
                };
                if(fields[f].length > 32) coltypes[f] = _BLOB;
                next->cols[f].name = 
                    (char *)apr_palloc(r->pool, (strlen(fields[f].name)+1) * sizeof(char));
                if(next->cols[f].name == NULL) OUT_OF_MEMORY;
                if(fields[f].name[0] == '@')
                    strcpy(next->cols[f].name, &fields[f].name[1]);
                else
                    strcpy(next->cols[f].name, fields[f].name);

                next->cols[f].vals = (db_val_t *)apr_palloc(r->pool,
                    next->num_rows * sizeof(db_val_t));
                if(next->cols[f].vals == NULL) OUT_OF_MEMORY;
                if(next->name == NULL && strlen(fields[f].table) > 0){
                    next->name = 
                        (char *)apr_palloc(r->pool, (strlen(fields[f].table) + 1) * sizeof(char));
                    if(next->name == NULL) OUT_OF_MEMORY;
                    strcpy(next->name, fields[f].table);
                };
            };
            for(ro = 0; ro < next->num_rows; ro++){
                row = mysql_fetch_row(result);
                if(row == NULL) break;
                lens = mysql_fetch_lengths(result);
                for(f = 0; f < next->num_fields; f++){
                    next->cols[f].vals[ro].type = coltypes[f];
                    next->cols[f].vals[ro].size = lens[f];
                    next->cols[f].vals[ro].val = 
                    (char *)apr_palloc(r->pool, (lens[f] + 1) * sizeof(char));
                    if(next->cols[f].vals[ro].val == NULL) OUT_OF_MEMORY;
                    memcpy(next->cols[f].vals[ro].val, row[f], lens[f]);
                    next->cols[f].vals[ro].val[lens[f]] = '\0';
                };
            };
            
            if(!mysql_more_results(mysql) && qsize > 0){ 
                /* This means we're looking at the last result - 
                    The INOUTs, OUTs, and session vars */
                next->name = (char *)apr_palloc(r->pool, 9 * sizeof(char));
                if(next->name == NULL) OUT_OF_MEMORY;
                strcpy(next->name, "PROC_OUT");
                if(last != NULL)
                    last->next = next;
            }else{
                if(next->name == NULL){
                    next->name = (char *)apr_palloc(r->pool, 7 * sizeof(char));
                    if(next->name == NULL) OUT_OF_MEMORY;
                    strcpy(next->name, "status");
                };
                if(last != NULL)
                    last->next = next;
                last = next;
                next = (modmvproc_table *)apr_palloc(r->pool, sizeof(modmvproc_table));
                if(next == NULL) OUT_OF_MEMORY;
                next->next = NULL;
            };
            mysql_free_result(result);
        };
        status = mysql_next_result(mysql);
        if(status > 0){
            return dbError(cfg, r, mysql);
        };
    }while(status == 0);
    
    if(tables->name == NULL){
        tables->name = (char *)apr_palloc(r->pool, 10 * sizeof(char));
        if(tables->name == NULL) OUT_OF_MEMORY;
        strcpy(tables->name, "no_result");
    };

    db_cleanup((mvpool_t *)cfg->pool, mysql);
    return tables;
}

#endif

