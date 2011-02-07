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

#ifndef _MVPROC_FILLER_H
#define _MVPROC_FILLER_H

#include "mvproc.h"

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
                continue;
            };
            break;
        case _ELSE:
            if(ifstate[ifdepth] == 0){
                ifstate[ifdepth] = 1;
                ap_rprintf(r, "%s", piece->follow_text);
            }else{
                piece = skip_ahead(piece, _IF, _ENDIF);
                continue;
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
                            fornests[fordepth].cur_row = cur_row;
                            fordepth++;
                            fornests[fordepth].table = piece->tag;
                            fornests[fordepth].num_rows = tmpTables->num_rows;
                            fornests[fordepth].cur_row = 0;
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
                    ap_rprintf(r, "%s", piece->follow_text);
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
            }else{
                ap_rprintf(r, "%s", "Missing ENDIF");
                return;
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
        case _TEMPLATE:
            if(ifstate[ifdepth] == 1){
                db_val = get_tag_value(r->pool, "mvp_template", tables, "PROC_OUT", 0);
                if(db_val != NULL && db_val->val != NULL && strlen(db_val->val) > 0){
                    incl = get_template(r->pool, cfg, db_val->val);
                    if(incl != NULL) 
                        fill_template(r, cfg, incl, tables, cur_table, cur_row);
                };
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

#endif

