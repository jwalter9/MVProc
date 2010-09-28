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

static db_val_t *get_tag_value(apr_pool_t *p, const char *tag, 
                               modmvproc_table *tables, 
                               char *cur_table, mvulong cur_row){
    char tmpTable[256];
    char tmpField[256];
    mvulong tmpRow = cur_row;
    strcpy(tmpTable, tag);
    char *nstr = strchr(tmpTable,'.');
    if(nstr != NULL){
        nstr[0] = '\0';
        if(strcmp(tmpTable, cur_table) != 0) tmpRow = 0;
        nstr++;
        strcpy(tmpField, nstr);
    }else{
        strcpy(tmpTable, cur_table);
        strcpy(tmpField, tag);
    };
    nstr = strchr(tmpField, '[');
    if(nstr != NULL){
        nstr[0] = '\0';
        nstr++;
        tmpRow = strspn(nstr, "0123456789");
        nstr[tmpRow] = '\0';
        tmpRow = atol(nstr);
    };
    return lookup(p, tables, tmpTable, tmpField, tmpRow);
}

static unsigned char eval_expr(apr_pool_t *p, modmvproc_table *tables, 
                              char *cur_table, mvulong cur_row, expression_t *exp){
    char *left;
    char *right;
    double dleft, dright;
    long lleft, lright;
    int i;
    db_val_t *val;
    db_col_type type = exp->type;
    left = exp->left;
    if(exp->cons_left == 0){
        val = get_tag_value(p, exp->left, tables, cur_table, cur_row);
        if(val == NULL || val->val == NULL) return 0;
        left = val->val;
        type = val->type;
    };
    if(exp->oper == _NULL) return (strlen(left) < 1 ? 1 : 0);
    if(exp->oper == _NOTNULL) return (strlen(left) > 0 ? 1 : 0);
    right = exp->right;
    if(exp->cons_right == 0){
        val = get_tag_value(p, exp->right, tables, cur_table, cur_row);
        if(val == NULL || val->val == NULL) return 0;
        right = val->val;
        type = val->type;
    };
    switch(type){
    case _DOUBLE:
        dleft = atof(left);
        dright = atof(right);
        if( (exp->oper == _EQ && dleft == dright) ||
            (exp->oper == _NE && dleft != dright) ||
            (exp->oper == _LT && dleft < dright) ||
            (exp->oper == _GT && dleft > dright) ||
            (exp->oper == _LTE && dleft <= dright) ||
            (exp->oper == _GTE && dleft >= dright) ) return 1;
        return 0;
        break;
    case _LONG:
        lleft = atol(left);
        lright = atol(right);
        if( (exp->oper == _EQ && lleft == lright) ||
            (exp->oper == _NE && lleft != lright) ||
            (exp->oper == _LT && lleft < lright) ||
            (exp->oper == _GT && lleft > lright) ||
            (exp->oper == _LTE && lleft <= lright) ||
            (exp->oper == _GTE && lleft >= lright) ) return 1;
        return 0;
        break;
    default:
        i = strcmp(left, right);
        if( (exp->oper == _EQ && i == 0) ||
            (exp->oper == _NE && i != 0) ||
            (exp->oper == _LT && i < 0) ||
            (exp->oper == _GT && i > 0) ||
            (exp->oper == _LTE && i <= 0) ||
            (exp->oper == _GTE && i >= 0) ) return 1;
        return 0;
    };
}

static unsigned char eval_cond(apr_pool_t *p, modmvproc_table *tables, 
    char *cur_table, int cur_row, cond_t *ifs){
    unsigned char eval = 1;
    if(ifs->exp != NULL)
        eval = eval_expr(p, tables, cur_table, cur_row, ifs->exp);
    if(ifs->deeper != NULL)
        eval = eval_cond(p, tables, cur_table, cur_row, ifs->deeper);
    if(eval == 0 && ifs->andc != NULL) return 0;
    if(eval == 1 && ifs->orc != NULL) return 1;
    if(ifs->orc != NULL)
        return eval_cond(p, tables, cur_table, cur_row, ifs->orc);
    if(ifs->andc != NULL)
        return eval_cond(p, tables, cur_table, cur_row, ifs->andc);
    return eval;
}

static template_segment_t *skip_ahead(template_segment_t *piece, int begin_tag, int end_tag){
    unsigned int tmpDepth = 0;
    piece = piece->next;
    while(piece != NULL){
        if(piece->type == begin_tag){
            tmpDepth++;
        }else if(piece->type == end_tag){
            if(tmpDepth == 0){
                return piece;
            }else{
                tmpDepth--;
            };
        };
        piece = piece->next;
    };
    return NULL;
}

static user_val_t *eval_set(apr_pool_t *p, modmvproc_table *tables, 
    char *cur_table, int cur_row, user_val_t *setv){
    long lval;
    double dval;
    double *tmpd = (double *)apr_palloc(p, sizeof(double));
    char *left;
    user_val_t *tmpset, *evalset, *first, *iter;
    db_val_t *tmpval;
    tmpset = (user_val_t *)apr_palloc(p, sizeof(user_val_t));
    if(tmpset == NULL) return NULL;
    tmpset->next = NULL;
    first = tmpset;
    iter = setv;
    /* create an expression of constants */
    while(iter != NULL){
        if(iter->deeper != NULL){
            evalset = eval_set(p, tables, cur_table, cur_row, iter->deeper);
            tmpset->type = evalset->type;
            tmpset->tag = evalset->tag;
        }else{
            if(iter->cons == 1){
                tmpset->type = iter->type;
                tmpset->tag = iter->tag;
            }else if(iter->oper != _SETVAL){
                tmpval = get_tag_value(p, iter->tag, tables, cur_table, cur_row);
                if(tmpval == NULL || tmpval->val == NULL) return NULL;
                tmpset->type = tmpval->type;
                tmpset->tag = tmpval->val;
            }else{
                tmpset->type = iter->type;
                tmpset->tag = iter->tag;
            };
        };
        tmpset->oper = iter->oper;
        if(iter->next != NULL){
            tmpset->next = (user_val_t *)apr_palloc(p, sizeof(user_val_t));
            if(tmpset->next == NULL) return NULL;
            tmpset = tmpset->next;
            tmpset->next = NULL;
        };
        iter = iter->next;
    };
    /* handle all *, /, & % */
    iter = first;
    while(iter != NULL){
        if(iter->next != NULL && (iter->oper == _MULTIPLY || 
            iter->oper == _DIVIDE || iter->oper == _MOD)){
            if(iter->type == _DOUBLE || iter->next->type == _DOUBLE){
                dval = atof(iter->tag);
                switch(iter->oper){
                case _MULTIPLY:
                    dval *= atof(iter->next->tag);
                    break;
                case _DIVIDE:
                    dval /= atof(iter->next->tag);
                    break;
                case _MOD:
                    dval /= atof(iter->next->tag);
                    dval = modf(dval, tmpd);
                    break;
                default:
                    break;
                };
                iter->tag = (char *)apr_palloc(p, 30 * sizeof(char));
                iter->type = _DOUBLE;
                sprintf(iter->tag, "%f", dval);
            }else{
                lval = atol(iter->tag);
                switch(iter->oper){
                case _MULTIPLY:
                    lval *= atol(iter->next->tag);
                    break;
                case _DIVIDE:
                    lval /= atol(iter->next->tag);
                    break;
                case _MOD:
                    lval %= atol(iter->next->tag);
                    break;
                default:
                    break;
                };
                iter->tag = (char *)apr_palloc(p, 20 * sizeof(char));
                sprintf(iter->tag, "%lu", lval);
            };
            iter->oper = iter->next->oper;
            iter->next = iter->next->next;
            continue;
        };
        iter = iter->next;
    };
    /* handle all + and - */
    iter = first;
    while(iter != NULL){
        if(iter->next != NULL && (iter->oper == _ADD || iter->oper == _SUBTRACT)){
            if((iter->type == _STRING || iter->next->type == _STRING) 
                && iter->oper == _ADD){
              left = (char *)apr_palloc(p, 
                  (strlen(iter->tag)+strlen(iter->next->tag)+1) * sizeof(char));
              strcpy(left, iter->tag);
              strcat(left, iter->next->tag);
              iter->tag = left;
            }else if(iter->type == _DOUBLE || iter->next->type == _DOUBLE){
                dval = atof(iter->tag);
                switch(iter->oper){
                case _ADD:
                    dval += atof(iter->next->tag);
                    break;
                case _SUBTRACT:
                    dval -= atof(iter->next->tag);
                    break;
                default:
                    break;
                };
                iter->tag = (char *)apr_palloc(p, 30 * sizeof(char));
                iter->type = _DOUBLE;
                sprintf(iter->tag, "%f", dval);
            }else{
                lval = atol(iter->tag);
                switch(iter->oper){
                case _ADD:
                    lval += atol(iter->next->tag);
                    break;
                case _SUBTRACT:
                    lval -= atol(iter->next->tag);
                    break;
                default:
                    break;
                };
                iter->tag = (char *)apr_palloc(p, 20 * sizeof(char));
                sprintf(iter->tag, "%lu", lval);
            };
            iter->oper = iter->next->oper;
            iter->next = iter->next->next;
            continue;
        };
        iter = iter->next;
    };
    iter = first;
    while(iter != NULL){
        if(iter->oper == _SETVAL){
            set_user_val(p, tables, iter->tag, iter->next);
            iter->tag = iter->next->tag;
            iter->type = iter->next->type;
        };
        iter = iter->next;
    };
    return first;
}

static template_cache_t *get_template(apr_pool_t *p, modmvproc_config *cfg, char *fname){
    if(!fname || strlen(fname) == 0)
        return NULL;

    template_cache_t *tpl = cfg->template_cache;
    while(tpl != NULL){
        if(strcmp(tpl->filename,fname) == 0)
            return tpl;
        tpl = tpl->next;
    };
    if(cfg->template_cache != NULL)
        return NULL;
    
    char *content = get_file_chars(p, cfg->template_dir, fname);
    if(content == NULL)
        return NULL;

    template_cache_t *next = parse_template(p, content);
    next->filename = fname;
    next->next = NULL;
    return next;
}

static void fill_template(request_rec *r, modmvproc_config *cfg, template_cache_t *tpl, 
                   modmvproc_table *tables, char *cur_table, mvulong cur_row){
    mvulong ifdepth = 0, fordepth = 0;
    unsigned int ifstate[MAX_NEST];
    ifstate[0] = 1;
    ifdepth = 0;
    fornest_tracker fornests[MAX_NEST];
    fornests[0].table = cur_table;
    fornests[0].cur_row = cur_row;
    fornests[0].num_rows = 0;
    mvulong skip;
    db_val_t *db_val;
    template_cache_t *incl;
    template_segment_t *piece = tpl->pieces;
    modmvproc_table *tmpTables;
    while(piece != NULL){
        switch(piece->type){
        case _NOTAG:
            if(ifstate[ifdepth] == 1)
                ap_rprintf(r, "%s", piece->follow_text);
            break;
        case _VALUE:
            if(ifstate[ifdepth] == 1){
                db_val = get_tag_value(r->pool, piece->tag, tables, cur_table, cur_row);
                if(db_val != NULL && db_val->val != NULL)
                    ap_rprintf(r, "%s%s",db_val->val,piece->follow_text);
                else
                    ap_rprintf(r, "%s",piece->follow_text);
            };
            break;
        case _IF:
            if(ifdepth >= MAX_NEST){
                ap_rprintf(r, "%s", "Maximum nested conditional depth exceeded.");
                break;
            };
            if(ifstate[ifdepth] == 1){
                ifdepth++;
                ifstate[ifdepth] = 0;
                if(eval_cond(r->pool, tables, cur_table, cur_row, piece->ifs) == 1){
                    ifstate[ifdepth] = 1;
                    ap_rprintf(r, "%s", piece->follow_text);
                };
            }else{
                piece = skip_ahead(piece, _IF, _ENDIF);
            };
            break;
        case _ELSIF:
            if(ifstate[ifdepth] == 0){
                if(eval_cond(r->pool, tables, cur_table, cur_row, piece->ifs) == 1){
                    ifstate[ifdepth] = 1;
                    ap_rprintf(r, "%s", piece->follow_text);
                };
            }else{
                piece = skip_ahead(piece, _IF, _ENDIF);
            };
            break;
        case _ELSE:
            if(ifstate[ifdepth] == 0){
                ifstate[ifdepth] = 1;
                ap_rprintf(r, "%s", piece->follow_text);
            }else{
                piece = skip_ahead(piece, _IF, _ENDIF);
            };
            break;
        case _ENDIF:
            if(ifdepth > 0) ifdepth--;
            if(ifstate[ifdepth] == 1){
                ap_rprintf(r, "%s", piece->follow_text);
            };
            break;
        case _LOOP: /* This code will only run at the first iteration of a loop */
            if(ifstate[ifdepth] == 1){
                skip = 1;
                tmpTables = tables;
                while(tmpTables != NULL){
                    if(strcmp(tmpTables->name, piece->tag) == 0){
                        if(tmpTables->num_rows > 0){
                            fordepth++;
                            fornests[fordepth].table = piece->tag;
                            fornests[fordepth].num_rows = tmpTables->num_rows;
                            fornests[fordepth].cur_row = cur_row;
                            fornests[fordepth].start_piece = piece;
                            cur_table = piece->tag;
                            cur_row = 0;
                            ap_rprintf(r, "%s", piece->follow_text);
                            skip = 0;
                        };
                        break;
                    };
                    tmpTables = tmpTables->next;
                };
                if(skip == 1){
                    piece = skip_ahead(piece, _LOOP, _ENDLOOP);
                };
            }else{
                piece = skip_ahead(piece, _LOOP, _ENDLOOP);
            };
            break;
        case _ENDLOOP:
            if(ifstate[ifdepth] == 1){ /* Should always be true to reach this... */
                cur_row++;
                if(cur_row < fornests[fordepth].num_rows){
                    piece = fornests[fordepth].start_piece;
                }else{
                    if(fordepth > 0) fordepth--;
                    cur_table = fornests[fordepth].table;
                    cur_row = fornests[fordepth].cur_row;
                };
                ap_rprintf(r, "%s", piece->follow_text);
            };
            break;
        case _INCLUDE:
            if(ifstate[ifdepth] == 1){
                incl = get_template(r->pool, cfg, piece->tag);
                if(incl != NULL) 
                    fill_template(r, cfg, incl, tables, cur_table, cur_row);
                ap_rprintf(r, "%s", piece->follow_text);
            };
            break;
        case _SET:
            if(ifstate[ifdepth] == 1){
                eval_set(r->pool, tables, cur_table, cur_row, piece->sets);
                ap_rprintf(r, "%s", piece->follow_text);
            };
            break;
        default:
            break;
        };
        if(piece == NULL){
            ap_rprintf(r, "%s", "Missing ENDIF or ENDLOOP");
            break;
        };
        piece = piece->next;
    };
}

static void xml_out(request_rec *r, modmvproc_config *cfg, modmvproc_table *tables){
    char *tchr;
    mvulong rind, cind, blobcount;
    ap_rprintf(r, "%s", "<?xml version='1.0' encoding='UTF-8'?><results>");
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
    mvulong rind, cind;
    ap_rprintf(r, "%s", "<?xml version='1.0' encoding='UTF-8'?><results>");
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
    char *tchr;
    mvulong rind, cind;
    ap_rprintf(r, "%s", "{\"table\":[");
    while(tables != NULL){
        ap_rprintf(r,"{\"name\":\"%s\",\"row\":[", tables->name);
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
    else if(cfg->output == _JSON)
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
            session_val = (char *)apr_palloc(r->pool, 33 * sizeof(char));
            time_t tim = time(NULL);
            sprintf(session_val,"%s%s",r->connection->remote_ip,asctime(localtime(&tim)));
            strncpy(session_val, ap_md5(apreq->pool, session_val), 32);
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
    else
        cfg->output = _XML_MIXED;
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
	return newcfg;
}

module AP_MODULE_DECLARE_DATA mvproc_module = 
    { STANDARD20_MODULE_STUFF, NULL, NULL, create_modmvproc_config, NULL, 
      modmvproc_cmds, modmvproc_register_hooks };

