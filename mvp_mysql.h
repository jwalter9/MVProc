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

#define OUT_OF_MEMORY \
    { ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Out of memory: apr_palloc returned NULL"); \
      mysql_close(mysql); \
    return NULL; }
    
static void fill_proc_struct(apr_pool_t *p, const char *pname, 
                             const char *paramList, modmvproc_cache *cache_entry){
    cache_entry->procname = (char *)apr_palloc(p, (strlen(pname)+1) * sizeof(char));
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
    mysql_init(&mysql);
    if(&mysql == NULL)
        return "Failed init";
    if(mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, cfg->group) != 0)
        return "Failed Option";
    if(mysql_real_connect(&mysql, NULL, NULL, NULL, NULL, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL)
        return mysql_error(&mysql);
    char query[1024];
    sprintf(query, "SELECT name, param_list FROM mysql.proc WHERE db='%s' AND type='PROCEDURE'",mysql.db);
    if(mysql_real_query(&mysql,query,strlen(query)) != 0) return;
    MYSQL_RES *result = mysql_store_result(&mysql);
    modmvproc_cache *ncache, *last = NULL;
    MYSQL_ROW row;
    while(NULL != (row = mysql_fetch_row(result))){
        ncache = (modmvproc_cache *)apr_palloc(p, sizeof(modmvproc_cache));
        fill_proc_struct(p, (char *)row[0], (char *)row[1], ncache);
        if(last != NULL) last->next = ncache;
        else cfg->cache = ncache;
        last = ncache;
    };
    mysql_free_result(result);
    mysql_close(&mysql);
    return NULL;
}

static modmvproc_table *getDBResult(modmvproc_config *cfg, request_rec *r,
                                    apreq_handle_t *apreq, const char *session_id){

    MYSQL *mysql = apr_palloc(r->pool, sizeof(MYSQL));
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

	modmvproc_cache *cache_entry = NULL;
	size_t qsize = 0, add_mem = 0, add_flag = 0, pos = 0;
    char *escaped;
    char procname[65];
    char uploaded[65];
    strcpy(procname, r->uri + sizeof(char)); /* first will be a '/' */
    if(procname[0] == '\0')
        strcpy(procname, "landing");
    MYSQL_RES *result;
    MYSQL_ROW row;

    const apreq_param_t *parsed_param;
    apr_file_t *fptr;
    apr_off_t *wlen;
    apr_status_t fstat;
    db_param_t *param;
    mvulong parm_ind = 0;

    if(cfg->cache != NULL){
        cache_entry = cfg->cache;
        while(cache_entry != NULL){
            if(apr_strnatcmp(cache_entry->procname,procname) == 0) break;
            if(cache_entry->next == NULL){
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                    "Request for unknown content: %s", procname);
                return NULL;
            };
            cache_entry = cache_entry->next;
        };
    }else{
        qsize = 85 + strlen(mysql->db) + strlen(procname);
        char *proc_query = apr_palloc(r->pool, qsize * sizeof(char));
        sprintf(proc_query, "SELECT name, param_list FROM mysql.proc WHERE db='%s' AND type='PROCEDURE' AND name='%s'",
            mysql->db, procname);
        if(mysql_real_query(mysql,proc_query,strlen(proc_query)) != 0){
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                "MYSQL Error (proc lookup query): %s", mysql_error(mysql));
            return NULL;
        };
        result = mysql_store_result(mysql);
        if(mysql_num_rows(result) < 1){
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                "Request for unknown content: %s", procname);
            mysql_free_result(result);
            return NULL;
        };
        row = mysql_fetch_row(result);
        if(row == NULL){
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                "MYSQL Error (proc lookup row fetch): %s",mysql_error(mysql));
            mysql_free_result(result);
            return NULL;
        };
        cache_entry = (modmvproc_cache *)apr_palloc(r->pool, (sizeof(modmvproc_cache)));
        if(cache_entry == NULL) OUT_OF_MEMORY;
        fill_proc_struct(r->pool, (char *)row[0], (char *)row[1], cache_entry);
    };

    /* starting size about twice minimum for headroom and changes */
    qsize = 512 + strlen(procname) + (
        strlen(session_id) + 
        strlen(r->server->server_hostname) +
        strlen(r->method) +
        strlen(r->unparsed_uri) +
        strlen(r->the_request) +
        strlen(r->connection->remote_ip)
        ) * 2; 
    parm_ind = 0;
    param = cache_entry->param_list;
    db_call_param inparms[cache_entry->num_params];
    while(param != NULL){
        uploaded[0] = '\0';
        parsed_param = apreq_param(apreq,param->name);
        if(parsed_param == NULL){
            inparms[parm_ind].val = (char *)apr_palloc(r->pool, sizeof(char));
            if(inparms[parm_ind].val == NULL) OUT_OF_MEMORY;
            inparms[parm_ind].val[0] = '\0';
        }else{
            if(parsed_param->upload != NULL){
                strcpy(uploaded, tmpnam(NULL));
                strcat(uploaded, strrchr(parsed_param->v.data, '.'));
                fstat = apr_file_open(&fptr, uploaded, APR_WRITE | APR_CREATE, APR_OS_DEFAULT, r->pool);
                if(fstat == APR_SUCCESS)
                    fstat = apreq_brigade_fwrite(fptr, wlen, parsed_param->upload);
                apr_file_close(fptr);
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
            qsize += strlen(inparms[parm_ind].val) + 4;
            break;
        case INOUT:
            qsize += strlen(param->name) * 2 + strlen(inparms[parm_ind].val) + 17;
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
    
    pos = 0;
    char query[qsize];
    for(parm_ind = 0; parm_ind < cache_entry->num_params; parm_ind++){
        switch(inparms[parm_ind].param->in_or_out){
        case INOUT:
            sprintf(&query[pos],"SET @%s = '%s'; ",
                inparms[parm_ind].param->name,inparms[parm_ind].val);
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
    
    if(cfg->session == 'Y' || cfg->session == 'y'){
        escaped = (char *)apr_palloc(r->pool, (strlen(session_id) * 2 + 1) * sizeof(char));
        if(escaped == NULL) OUT_OF_MEMORY;
        mysql_real_escape_string(mysql, escaped, session_id, strlen(session_id));
        sprintf(&query[pos],"SET @mvp_session = '%s'; ", escaped);
        pos = strlen(query);
    };
    
    escaped = (char *)apr_palloc(r->pool, (strlen(r->server->server_hostname) * 2 + 1) * sizeof(char));
    if(escaped == NULL) OUT_OF_MEMORY;
    mysql_real_escape_string(mysql, escaped, r->server->server_hostname, strlen(r->server->server_hostname));
    sprintf(&query[pos], "SET @mvp_servername = '%s'; ", escaped);
    pos = strlen(query);
    
    escaped = (char *)apr_palloc(r->pool, (strlen(r->method) * 2 + 1) * sizeof(char));
    if(escaped == NULL) OUT_OF_MEMORY;
    mysql_real_escape_string(mysql, escaped, r->method, strlen(r->method));
    sprintf(&query[pos], "SET @mvp_requestmethod = '%s'; ", escaped);
    pos = strlen(query);
    
    escaped = (char *)apr_palloc(r->pool, (strlen(r->unparsed_uri) * 2 + 1) * sizeof(char));
    if(escaped == NULL) OUT_OF_MEMORY;
    mysql_real_escape_string(mysql, escaped, r->unparsed_uri, strlen(r->unparsed_uri));
    sprintf(&query[pos], "SET @mvp_uri = '%s'; ", escaped);
    pos = strlen(query);
    
    escaped = (char *)apr_palloc(r->pool, (strlen(procname) * 2 + 1) * sizeof(char));
    if(escaped == NULL) OUT_OF_MEMORY;
    mysql_real_escape_string(mysql, escaped, procname, strlen(procname));
    sprintf(&query[pos], "SET @mvp_template = '%s'; ", escaped);
    pos = strlen(query);
    
    escaped = (char *)apr_palloc(r->pool, (strlen(r->the_request) * 2 + 1) * sizeof(char));
    if(escaped == NULL) OUT_OF_MEMORY;
    mysql_real_escape_string(mysql, escaped, r->the_request, strlen(r->the_request));
    sprintf(&query[pos], "SET @mvp_headers = '%s'; ", escaped);
    pos = strlen(query);
    
    escaped = (char *)apr_palloc(r->pool, (strlen(r->connection->remote_ip) * 2 + 1) * sizeof(char));
    if(escaped == NULL) OUT_OF_MEMORY;
    mysql_real_escape_string(mysql, escaped, r->connection->remote_ip, strlen(r->connection->remote_ip));
    sprintf(&query[pos], "SET @mvp_remoteip = '%s'; ", escaped);
    pos = strlen(query);

    sprintf(&query[pos], "CALL %s(",cache_entry->procname);
    pos = strlen(query);
    param = cache_entry->param_list;
    for(parm_ind = 0; parm_ind < cache_entry->num_params; parm_ind++){
        switch(inparms[parm_ind].param->in_or_out){
        case IN:
            sprintf(&query[pos],"'%s'", inparms[parm_ind].val);
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

    sprintf(&query[pos]," SELECT ");
    pos += 8;
    
    if(cfg->session == 'Y' || cfg->session == 'y'){
        sprintf(&query[pos],"@mvp_session, ");
        pos += 14;
    };
    
    for(parm_ind = 0; parm_ind < cache_entry->num_params; parm_ind++){
        switch(inparms[parm_ind].param->in_or_out){
        case INOUT:
        case OUT:
            sprintf(&query[pos],"@%s, ",inparms[parm_ind].param->name);
            pos = strlen(query);
            break;
        default:
            break;
        };
    };

    sprintf(&query[pos],"@mvp_template;");
    pos += 14;
    
    if(mysql_real_query(mysql,query,strlen(query)) != 0){
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MYSQL Error (CALL query): %s", mysql_error(mysql));
        return NULL;
    };

    int status;
    mvulong index = 0, f, ro, c, col_index, *lens;
    db_col_type *coltypes;
    MYSQL_FIELD *fields;
    
    modmvproc_table *next = 
    (modmvproc_table *)apr_palloc(r->pool, sizeof(modmvproc_table));
    if(next == NULL) OUT_OF_MEMORY;
    next->next = NULL;
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
            
            if(!mysql_more_results(mysql)){ 
                /* This means we're looking at the last result - 
                    The INOUTs, OUTs, and session vars */
                next->name = (char *)apr_palloc(r->pool, 9 * sizeof(char));
                if(next->name == NULL) OUT_OF_MEMORY;
                strcpy(next->name, "PROC_OUT");
                if(last != NULL)
                    last->next = next;
            }else{
                if(strlen(fields[0].table) > 0){
                    next->name = 
                        (char *)apr_palloc(r->pool, (strlen(fields[0].table) + 1) * sizeof(char));
                    if(next->name == NULL) OUT_OF_MEMORY;
                    strcpy(next->name, fields[0].table);
                }else{
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MYSQL Error (next result): %s", mysql_error(mysql));
            mysql_close(mysql);
            return NULL;
        };
    }while(status == 0);

    mysql_close(mysql);
    return tables;
}

#endif

