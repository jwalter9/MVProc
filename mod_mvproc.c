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

#include "mvproc.h"
#include "mvp_mysql.h"
#include "parser.h"
#include "filler.h"


static void xml_out(request_rec *r, modmvproc_config *cfg, modmvproc_table *tables){
    char *tchr = (char *)apr_palloc(r->pool, 21 * sizeof(char));
    if(tchr == NULL)
        ap_rprintf(r, "%s", "Memory allocation failure");
    mvulong rind, cind, blobcount;
    time_t tim = time(NULL);
    strftime(tchr,20,"%Y-%m-%d %H:%M:%S",localtime(&tim));
    ap_rprintf(r, 
        "<?xml version='1.0' encoding='UTF-8'?><results server_datetime='%s'>",
        tchr);
    while(tables != NULL){
        ap_rprintf(r,"<table name='%s'>", tables->name);
        for(rind = 0; rind < tables->num_rows; rind++){
            blobcount = 0;
            ap_rprintf(r, "%s", "<row ");
            for(cind = 0; cind < tables->num_fields; cind++){
                if(tables->cols[cind].vals[rind].type == _BLOB){
                    blobcount++;
                }else{
                    tchr = ap_escape_quotes(r->pool, tables->cols[cind].vals[rind].val);
                    ap_rprintf(r,"%s=\"%s\" ",tables->cols[cind].name,tchr);
                };
            };
            if(blobcount == 0){
                ap_rprintf(r, "%s", "/>");
            }else{
                ap_rprintf(r, "%s", ">");
                for(cind = 0; cind < tables->num_fields; cind++){
                    if(tables->cols[cind].vals[rind].type == _BLOB){
                        ap_rprintf(r, "<%s><![CDATA[",tables->cols[cind].name);
                        ap_rwrite(tables->cols[cind].vals[rind].val, 
                            tables->cols[cind].vals[rind].size, r);
                        ap_rprintf(r, "]]></%s>",tables->cols[cind].name);
                    };
                };
                ap_rprintf(r, "%s", "</row>");
            };
        };
        ap_rprintf(r, "%s", "</table>");
        tables = tables->next;
    };
    ap_rprintf(r, "%s", "</results>\r\n");
    return;
}

static void xml_plain(request_rec *r, modmvproc_config *cfg, modmvproc_table *tables){
    char *tchr = (char *)apr_palloc(r->pool, 21 * sizeof(char));
    if(tchr == NULL)
        ap_rprintf(r, "%s", "Memory allocation failure");
    mvulong rind, cind;
    time_t tim = time(NULL);
    strftime(tchr,20,"%Y-%m-%d %H:%M:%S",localtime(&tim));
    ap_rprintf(r, 
        "<?xml version='1.0' encoding='UTF-8'?><results server_datetime='%s'>",
        tchr);
    while(tables != NULL){
        ap_rprintf(r,"<table name='%s'>", tables->name);
        for(rind = 0; rind < tables->num_rows; rind++){
            ap_rprintf(r, "%s", "<row>");
            for(cind = 0; cind < tables->num_fields; cind++){
                ap_rprintf(r, "<%s><![CDATA[",tables->cols[cind].name);
                ap_rwrite(tables->cols[cind].vals[rind].val, 
                    tables->cols[cind].vals[rind].size, r);
                ap_rprintf(r, "]]></%s>",tables->cols[cind].name);
            };
            ap_rprintf(r, "%s", "</row>");
        };
        ap_rprintf(r, "%s", "</table>");
        tables = tables->next;
    };
    ap_rprintf(r, "%s", "</results>\r\n");
    return;
}

static void json_out(request_rec *r, modmvproc_config *cfg, modmvproc_table *tables){
    char *tchr = (char *)apr_palloc(r->pool, 21 * sizeof(char));
    if(tchr == NULL)
        ap_rprintf(r, "%s", "Memory allocation failure");
    mvulong rind, cind;
    time_t tim = time(NULL);
    strftime(tchr,20,"%Y-%m-%d %H:%M:%S",localtime(&tim));
    ap_rprintf(r, "{\"server_datetime\":\"%s\",\"table\":[", tchr);
    while(tables != NULL){
        ap_rprintf(r,"{\"name\":\"%s\"%s", tables->name,
            tables->num_rows > 0 ? ",\"row\":[": "");
        for(rind = 0; rind < tables->num_rows; rind++){
            ap_rprintf(r, "%s", "{");
            for(cind = 0; cind < tables->num_fields; cind++){
                tchr = ap_escape_quotes(r->pool, tables->cols[cind].vals[rind].val);
                if(tables->num_fields - cind > 1)
                    ap_rprintf(r,"\"%s\":\"%s\",",tables->cols[cind].name,tchr);
                else
                    ap_rprintf(r,"\"%s\":\"%s\"",tables->cols[cind].name,tchr);
            };
            if(tables->num_rows - rind > 1) ap_rprintf(r, "%s", "},");
            else ap_rprintf(r, "%s", "}]");
        };
        ap_rprintf(r, "%s", "}");
        if(tables->next != NULL) ap_rprintf(r, "%s", ",");
        tables = tables->next;
    };
    ap_rprintf(r, "%s", "]}\r\n");
    return;
}

static void easier_json_out(request_rec *r, modmvproc_config *cfg, modmvproc_table *tables){
    char *tchr = (char *)apr_palloc(r->pool, 21 * sizeof(char));
    if(tchr == NULL)
        ap_rprintf(r, "%s", "Memory allocation failure");
    mvulong rind, cind;
    time_t tim = time(NULL);
    strftime(tchr,20,"%Y-%m-%d %H:%M:%S",localtime(&tim));
    ap_rprintf(r, "{\"server_datetime\":\"%s\"", tchr);
    while(tables != NULL){
        if(tables->num_rows < 1){
            tables = tables->next;
            continue;
        };
        ap_rprintf(r,",\"%s\":[", tables->name);
        for(rind = 0; rind < tables->num_rows; rind++){
            ap_rprintf(r, "%s", "{");
            for(cind = 0; cind < tables->num_fields; cind++){
                tchr = ap_escape_quotes(r->pool, tables->cols[cind].vals[rind].val);
                ap_rprintf(r,"\"%s\":\"%s\"%s",tables->cols[cind].name,tchr,
                    tables->num_fields - cind > 1 ? "," : "");
            };
            ap_rprintf(r, "}%s", tables->num_rows - rind > 1 ? "," : "]");
        };
        tables = tables->next;
    };
    ap_rprintf(r, "%s", "}\r\n");
    return;
}

static void generate_output(request_rec *r, modmvproc_config *cfg, 
                            modmvproc_table *tables, apreq_cookie_t *ck){

    template_cache_t *template = NULL;
    if(cfg->template_dir != NULL && strlen(cfg->template_dir) > 0){
        db_val_t *tval = lookup(r->pool, tables, "PROC_OUT", "mvp_template", 0);
        if(tval != NULL && tval->val != NULL && strlen(tval->val) > 0)
        template = get_template(r->pool, cfg, tval->val);
    };

    if(template != NULL)
        ap_set_content_type(r, "text/html");
    else if(cfg->output == _JSON || cfg->output == _JSON_EASY)
        ap_set_content_type(r, "application/json");
    else
        ap_set_content_type(r, "text/xml");

    if(ck != NULL)
        apr_table_set(r->headers_out, "Set-Cookie", apreq_cookie_as_string(ck, r->pool));
    if(template == NULL){
        switch(cfg->output){
        case _XML_NO_ATTR:
            xml_plain(r, cfg, tables);
            break;
        case _JSON:
            json_out(r, cfg, tables);
            break;
        case _JSON_EASY:
            easier_json_out(r, cfg, tables);
            break;
        default:
            xml_out(r, cfg, tables);
        };
    }else{
        fill_template(r, cfg, template, tables, "PROC_OUT", 0);
        ap_rprintf(r, "%s", "\n");
    };
}


module AP_MODULE_DECLARE_DATA mvproc_module;

static int modmvproc_handler (request_rec *r){
    apreq_handle_t *apreq = apreq_handle_apache2(r);
    struct stat file_status;
    if(strcmp(r->uri, "/") != 0 && stat(r->filename, &file_status) == 0) return DECLINED;
    if(strlen(r->uri) > 65) return DECLINED;
    
	modmvproc_config *cfg = ap_get_module_config(r->server->module_config, &mvproc_module);
    apreq_cookie_t *session_cookie = NULL;
    /* Start session? */
    char *session_val;
    if(cfg->session == 'Y' || cfg->session == 'y'){
        session_cookie = apreq_jar_get(apreq, "MVPSESSION");
        if(session_cookie == NULL){
            session_val = (char *)apr_palloc(r->pool, 36 * sizeof(char));
            time_t tim = time(NULL);
            sprintf(session_val,"%s",r->connection->remote_ip);
            strftime(&session_val[strlen(session_val)],20,"%Y-%m-%d %H:%M:%S",localtime(&tim));
            strncpy(session_val, ap_md5(apreq->pool, (unsigned char *)session_val), 32);
            session_val[32] = '\0';
        }else{
            session_val = (char *)apr_palloc(r->pool, (session_cookie->v.dlen + 1) * sizeof(char));
            strcpy(session_val, session_cookie->v.data);
        };
    }else{
        session_val = (char *)apr_palloc(r->pool, sizeof(char));
        session_val[0] = '\0';
    };
    
    int *err = (int *)apr_palloc(r->pool, sizeof(int));
    if(err == NULL) return 500;
    *err = 500;
    modmvproc_table *tables = getDBResult(cfg, r, apreq, session_val, err);

    if(tables == NULL) return *err;
    db_val_t *scv = lookup(r->pool, tables, "PROC_OUT", "mvp_session", 0);

    if(scv != NULL && (cfg->session == 'Y' || cfg->session == 'y') &&
        (strcmp(session_val, scv->val) != 0 || session_cookie == NULL))
        session_cookie = 
        apreq_cookie_make(r->pool,"MVPSESSION",10,scv->val,strlen(scv->val));
    
    /* PARSE TEMPLATE OR OUTPUT XML */
    generate_output(r, cfg, tables, session_cookie);

	return DONE;
}

static void modmvproc_register_hooks (apr_pool_t *p){
	ap_hook_handler(modmvproc_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_template_dir(cmd_parms *parms, void *mconfig, const char *arg){
	modmvproc_config *cfg = ap_get_module_config(parms->server->module_config, &mvproc_module);
	cfg->template_dir = (char *)apr_palloc(parms->server->process->pconf, 
	                                       (strlen(arg)+2) * sizeof(char));
	if(cfg->template_dir == NULL) return "OUT OF MEMORY";
	strcpy(cfg->template_dir, arg);
    size_t pos = strlen(cfg->template_dir);
    if(cfg->template_dir[pos-1] != '/')
        strcpy(&cfg->template_dir[pos], "/");
	return NULL;
}

static const char *set_db_group(cmd_parms *parms, void *mconfig, const char *arg){
	modmvproc_config *cfg = ap_get_module_config(parms->server->module_config, &mvproc_module);
	cfg->group = (char *)apr_palloc(parms->server->process->pconf, 
	                                (strlen(arg)+1) * sizeof(char));
	if(cfg->group == NULL) return "OUT OF MEMORY";
	strcpy(cfg->group, arg);
	return NULL;
}

static const char *set_session(cmd_parms *parms, void *mconfig, const char *arg){
	modmvproc_config *cfg = ap_get_module_config(parms->server->module_config, &mvproc_module);
	cfg->session = arg[0];
	return NULL;
}

static const char *maybe_build_cache(cmd_parms *parms, void *mconfig, const char *arg){
	modmvproc_config *cfg = ap_get_module_config(parms->server->module_config, &mvproc_module);
	if(cfg->group == NULL)
	    return "mvprocCache directive must follow mvprocDbGroup directive";
	// Turn on caching ONLY if explicitly specified
    if(arg[0] != 'Y' && arg[0] != 'y') return NULL;
    const char *cv = build_cache(parms->server->process->pconf, cfg);
    if(cv == NULL && cfg->template_dir != NULL)
        cv = build_template_cache(parms->server->process->pconf, cfg);
    return cv;
}

static const char *maybe_make_pool(cmd_parms *parms, void *mconfig, const char *arg){
	modmvproc_config *cfg = ap_get_module_config(parms->server->module_config, &mvproc_module);
	if(cfg->group == NULL)
	    return "mvprocDbPoolSize directive must follow mvprocDbGroup directive";
	unsigned long num = atol(arg);
	if(num == 0) return NULL;
	return make_pool(parms->server->process->pconf, cfg, num);
}

static const char *set_out_type(cmd_parms *parms, void *mconfig, const char *arg){
    modmvproc_config *cfg = ap_get_module_config(parms->server->module_config, &mvproc_module);
    if(strcmp(arg, "PLAIN") == 0 || strcmp(arg,"plain") == 0)
        cfg->output = _XML_NO_ATTR;
    else if(strcmp(arg, "JSON") == 0 || strcmp(arg,"json") == 0)
        cfg->output = _JSON;
    else if(strcmp(arg, "EASY_JSON") == 0 || strcmp(arg,"easy_json") == 0)
        cfg->output = _JSON_EASY;
    else
        cfg->output = _XML_MIXED;
    return NULL;
}

static const char *set_error_tpl(cmd_parms *parms, void *mconfig, const char *arg){
    modmvproc_config *cfg = ap_get_module_config(parms->server->module_config, &mvproc_module);
	cfg->error_tpl = (char *)apr_palloc(parms->server->process->pconf, 
	                                    (strlen(arg)+1) * sizeof(char));
	if(cfg->error_tpl == NULL) return "OUT OF MEMORY";
    strcpy(cfg->error_tpl, arg);
    return NULL;
}

static const command_rec modmvproc_cmds[] = {
    AP_INIT_TAKE1("mvprocSession", set_session, NULL, RSRC_CONF, 
        "Session cookie: Y or N."),
    AP_INIT_TAKE1("mvprocTemplateDir", set_template_dir, NULL, RSRC_CONF, 
        "Full path to template directory."),
    AP_INIT_TAKE1("mvprocDbGroup", set_db_group, NULL, RSRC_CONF, 
        "Db Group defined in /etc/mysql/my.cnf"),
    AP_INIT_TAKE1("mvprocCache", maybe_build_cache, NULL, RSRC_CONF, 
        "Cache - Y for production, N for development."),
    AP_INIT_TAKE1("mvprocDbPoolSize", maybe_make_pool, NULL, RSRC_CONF, 
        "The number of connections to maintain."),
    AP_INIT_TAKE1("mvprocOutputStyle", set_out_type, NULL, RSRC_CONF, 
        "The default output: PLAIN, JSON, or MIXED"),
    AP_INIT_TAKE1("mvprocErrTemplate", set_error_tpl, NULL, RSRC_CONF, 
        "The template for displaying db errors."),
	{NULL}
};

static void *create_modmvproc_config(apr_pool_t *p, server_rec *s){
	modmvproc_config *newcfg;
	newcfg = (modmvproc_config *) apr_pcalloc(p, sizeof(modmvproc_config));
	newcfg->cache = NULL;
	newcfg->template_cache = NULL;
	newcfg->pool = NULL;
	newcfg->group = NULL;
	newcfg->output = _XML_MIXED;
	newcfg->error_tpl = NULL;
	return newcfg;
}

module AP_MODULE_DECLARE_DATA mvproc_module = 
    { STANDARD20_MODULE_STUFF, NULL, NULL, create_modmvproc_config, NULL, 
      modmvproc_cmds, modmvproc_register_hooks };

