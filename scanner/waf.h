/**
 * @file: waf.h
 * @desc:
 *
 * Fan pengfei,  2018/11/27
 *
 * Copyright (c) 2018, jd.com.
 * Copyright (c) 2018, jdcloud.com.
 * All rights reserved.
 **/

#define COMMIT_ID ""

#ifdef __cplusplus
extern "C"{
#endif

#ifndef __WAF_H
#define __WAF_H

#include <stdlib.h>
#include "waf.h"

#define PAYLOAD_LEN                 50
#define PAYLOAD_AFTER_LEN_DEFAULT   50
#define PAYLOAD_MAX_LEN_DEFAULT     300

#define RULE_RESULT_MAX          64 /* 最大返回结果数目 */
#define POLICYS_RESULT_MAX       64
#define POLICY_RULES_MAX         64 /* 每个Policy包含的最大子规则数目 */
#define WAF_RULE_MZ_LEN          64
#define WAF_SA_LEN               64
#define WAF_MZ_MAX               64 /* 匹配域的最大数量 */
#define WAF_SA_FP_LEN            8 /* 语义解析指纹最大长度 */

#define WAF_MATCH_OK      0
#define WAF_MATCH_ERR   -1

#define WAF_SYSLOG_TITLE        "WAF-ENGINE"

#define WAF_MATCHED         1
#define WAF_NOT_MATCH       0
#define WAF_MATCHING        2
#define WAF_NOT_FOUND       3

/* 不区分阶段， header和body等数据一次性传入 */
#define WAF_PHASE_ANY       0x0   

#define WAF_BODY_TYPE_REQ   0x0
#define WAF_BODY_TYPE_RESP  0x1

#define WAFSDK_MAGIC 0xAABBCDEF

typedef enum {
    WAFSDK_ACT_NONE = 0, 
    WAFSDK_ACT_LOG = 1,  
    WAFSDK_ACT_BLOCK =2 
} wafsdk_action_e;

#define WAFSDK_ACT_NONE_STR     (char *)"none"
#define WAFSDK_ACT_LOG_STR      (char *)"log"
#define WAFSDK_ACT_BLOCK_STR    (char *)"block"

typedef enum {
    WAF_PHASE_REQ = 1, //1
    WAF_PHASE_REQ_HEADER, //2
    WAF_PHASE_REQ_BODY, //3
    WAF_PHASE_RESP,  //4
    WAF_PHASE_RESP_HEADER, //5
    WAF_PHASE_RESP_BODY //6
} waf_phase_e;

/* 语义解析结果集 */
typedef struct {
    int action; 
    char mz[WAF_RULE_MZ_LEN];

    unsigned char *payload;
    unsigned int payload_len;

    unsigned char *payload_after;
    unsigned int payload_after_len;

    int isxss;
    int issqli; 
    char sa_type[64];  /* white | black */
    char sa_name[64];  
    char sa_action[64];  
    char sa_value[64];

    waf_phase_e phase;
} sa_result_t;

typedef struct {
    int         rule_id;
    char          *start_ori;
    char          *start;
    unsigned int  from;
    unsigned int  to; 

    /* 需要拷贝， 因为可能存在多个chain, 
     * 如果不拷贝在下一个chain会丢失当前的指针 */
    unsigned char *payload; /* point to hit end */
    unsigned int payload_len;
    unsigned char *payload_after;  /* point to hit after post */
    unsigned int payload_after_len;

    waf_phase_e phase;
    char mz[WAF_MZ_MAX];
} rule_result_t;

typedef struct {
    int policy_id;
    int policy_action;
    //char policy_action[WAF_RULE_MZ_LEN];
    rule_result_t *results[POLICY_RULES_MAX];  /* point to rules[i] */
    unsigned int cursor;
    int match_state; /* WAF_NOT_MATCH WAF_MATCHING WAF_MATCHED */

    waf_phase_e phase;
} policy_result_t;

typedef struct {
    rule_result_t *rule_results[RULE_RESULT_MAX];
    unsigned int rule_cursor;

    policy_result_t *policy_results;
    unsigned int policy_cursor;

    policy_result_t **policy_hit_results;
    unsigned int policy_hit_cursor;

    sa_result_t *sa_results[WAF_MZ_MAX];
    unsigned int sa_cursor;
} match_result_t;


#if 0

//0000FFFF
#define MD_NOT_MATCHED          0x0
#define MD_HS_MATCHED           0x1
#define MD_SA_SQLI_MATCHED      0x10
#define MD_SA_XSS_MATCHED       0x100

//FFFF0000
#define MD_HS_U_MATCHED         0x10000
#define MD_SA_U_SQLI_MATCHED    0x100000
#define MD_SA_U_XSS_MATCHED     0x1000000

#define MD_MATCHED              0x0000ffff
#define MD_U_MATCHED            0xffff0000

#else

//ffffffff
#define MD_NOT_MATCHED          0x0

#define MD_HS_MATCHED           0x1
#define MD_SA_SQLI_MATCHED      0x10
#define MD_SA_XSS_MATCHED       0x100

//ffffffff00000000
#define MD_HS_U_MATCHED         0x10000000
#define MD_SA_U_SQLI_MATCHED    0x100000000
#define MD_SA_U_XSS_MATCHED     0x1000000000
#define MD_HS_U_D_MATCHED       0x10000000000
#define MD_HS_U_D_T_MATCHED     0x100000000000

#define MD_MATCHED              0x00000000ffffffff
#define MD_U_MATCHED            0xffffffff00000000

#endif

typedef struct {
    char *data;
    size_t dlen;
    int is_copy;

    unsigned int hash; 
    int self_clone;
	size_t matched;		  /*是否已经匹配过, 1-匹配过; 0-未匹配 */
	size_t match_status;  /* 00000000 00000000 ~ ffffffff ffffffff */
    int init_result;
    match_result_t *result;
} match_data_t;


#define INIT_MATCH_DATA(name, data, dlen)  \
        match_data_t name = { data, dlen, 0, 0, NULL, 0, 0 }

#define INIT_MATCH_DATA_CPY(name, data, dlen)       \
        match_data_t name = { data, dlen, 1, 0, NULL, 0, 0 }

#define WAF_VAR_KEY_URL             "url"
#define WAF_VAR_KEY_REQUEST_URI     "request_uri"
#define WAF_HDR_KEY_USER_AGENT      "User-Agent"
#define WAF_HDR_KEY_REFERER         "Referer"
#define WAF_VAR_RESPONSE_BODY       "response_body"

/* ==================== ALL default match zones =================== */
/* original text */
#define WAF_MZ_URI                  "$uri"              /* uri */
#define WAF_MZ_ARGS                 "$args"             /* args */
#define WAF_MZ_HTTP_URL             "$url"              
#define WAF_MZ_REQUEST_URI          "$request_uri"      /* uri + args */
#define WAF_MZ_REQUEST_BODY         "$request_body"     /* request_body */
#define WAF_MZ_HTTP_REFERER         "$http_referer"     
#define WAF_MZ_HTTP_USER_AGENT      "$http_user_agent"  
#define WAF_MZ_RESPONSE_BODY        "$response_body" 

#define WAF_MZ_HTTP_COOKIE          "$http_cookie"      /* cookies */
#define WAF_MZ_REQUEST_HEADERS      "$request_headers"  /* headers */
#define WAF_MZ_RESPONSE_HEADERS     "$response_headers" /* headers */
#define WAF_MZ_U_RESPONSE_HEADERS   "$u_response_headers" /* headers */

/* html decode */
#define WAF_MZ_U_URI                "$u_uri"            /* uri */
#define WAF_MZ_U_ARGS               "$u_args"           /* args */
#define WAF_MZ_U_ARGS_KV            "$U_ARGS"           /* args */
#define WAF_MZ_U_REQUEST_URI        "$u_request_uri"    /* uri + args */
#define WAF_MZ_U_REQUEST_BODY       "$u_request_body"   /* request_body */
#define WAF_MZ_U_HTTP_REFERER       "$u_http_referer"   /* referer */
#define WAF_MZ_U_HTTP_USER_AGENT    "$u_http_user_agent" /* ua */
#define WAF_MZ_U_HTTP_URL           "$u_url"            /* url */
#define WAF_MZ_U_HTTP_COOKIE        "$u_http_cookie"    /* cookies */
#define WAF_MZ_U_REQUEST_HEADERS    "$u_request_headers"    /* headers */
#define WAF_MZ_U_REQUEST_HEADERS_VAL "$U_REQUEST_HEADERS"    /* headers */
#define WAF_MZ_U_RESPONSE_BODY      "$u_response_body" 
#define WAF_MZ_U_REQUEST_METHOD     "$u_request_method"
#define WAF_MZ_U_REQUEST_URI_PATH   "$u_request_uri_path"

/* auto match decode && 策略匹配阶段确定 */
#define WAF_MZ_U_GET_KEY            "$u_get_key"
#define WAF_MZ_U_GET_VALUE          "$u_get_value"
#define WAF_MZ_U_COOKIE_KEY         "$u_cookie_key"
#define WAF_MZ_U_COOKIE_VALUE       "$u_cookie_value"
#define WAF_MZ_ARGS_KEY             "$args_key"
#define WAF_MZ_ARGS_VALUE           "$args_value"
#define WAF_MZ_U_ARGS_KEY           "$u_args_key"
#define WAF_MZ_U_ARGS_VALUE         "$u_args_value"
#define WAF_MZ_U_POST_KEY           "$u_post_key"
#define WAF_MZ_U_POST_VALUE         "$u_post_value"

#define WAF_MZ_U_POST_ARGS_VALUE    "$u_post_args_value"
#define WAF_MZ_POST_ARGS_VALUE      "$post_args_value"

#define WAF_MZ_FILE_NAME            "$file_name"
#define WAF_MZ_FILE_CONTENT         "$file_content"
#define WAF_MZ_REQUEST_METHOD       "$request_method"

#define WAF_MZ_U_D_GET_VALUE        "$u_d_get_value"
#define WAF_MZ_U_D_POST_VALUE       "$u_d_post_value"
#define WAF_MZ_U_D_HTTP_URL         "$u_d_url"
#define WAF_MZ_U_D_REQUEST_HEADERS  "$u_d_request_headers"
#define WAF_MZ_U_D_REQUEST_BODY     "$u_d_request_body"

//灰度匹配域
#define WAF_MZ_U_D_T_GET_VALUE        "$u_d_t_get_value"
#define WAF_MZ_U_D_T_POST_VALUE       "$u_d_t_post_value"
#define WAF_MZ_U_D_T_HTTP_URL         "$u_d_t_url"
#define WAF_MZ_U_D_T_REQUEST_HEADERS  "$u_d_t_request_headers"

#define WAF_MZ_GET_VALUE			"$get_value"
#define WAF_MZ_POST_VALUE			"$post_value"
#define WAF_MZ_COOKIE_VALUE         "$cookie_value"

#define WAF_MZ_U_PREFIX             "$u_"
#define WAF_MZ_HPP_PREFIX           "$u_d_"
#define WAF_MZ_HPP_TEST_PREFIX      "$u_d_t_"


/* ==================== ALL default match zones END =================== */

/* ================= waf API ==================== */

/* ============================  WAF Handler API =======================  */
/* FUNCTION: Init WAF handler from waf config file */
void * waf_init(const char *waf_config_name, const char *logfile);

/* FUNCTION: Init WAF handler from json buffer */
void * waf_init_from_json_buf(const char *json_buf, size_t json_buf_len);

/* FUNCTION: show WAF handler */
void waf_show(void *waf_handler);

/* FUNCTION: finish WAF handler */
void waf_fini(void *waf_handler);

void *waf_ctx_init(void *waf);
void waf_ctx_fini(void *waf_ctx);

/* FUNCTION: WAF match 
 * @phase: 
 *  如果: header + body 一次性传入， 则phase WAF_PHASE_ANY
 *  否则： 
 *      header阶段传入WAF_PHASE_HEADER 
 *      body阶段传入WAF_PHASE_BODY
 * */
int waf_match(void *waf_handler, void *waf_mctx, void *waf_data, waf_phase_e phase);

/* FUNCTION: show all rule results */
void waf_match_result_free(match_result_t *r);

/* FUNCTION: 
 * @policyid - in
 * 
 * RETURN: 
 *      返回NULL 未找到对应策略的结果； 非空找到策略的结果;
 *      如果返回结果不为NULL, 需要进一步判断 policy_result_t->match_state状态，
 *      状态为 WAF_NOT_MATCH | WAF_MATCHING | WAF_MATCHED
 */
policy_result_t *waf_match_policy_result_get(void *waf_data, int policyid);

/* FUNCTION: WAF result show */
void waf_result_show(void *match_res);

/* ================================ WAF data API ========================== */
#define HTTP_UNKNOWN    0
#define HTTP_GET        1
#define HTTP_HEAD       2
#define HTTP_POST       3
#define HTTP_PUT        4
#define HTTP_DELETE     5
#define HTTP_MKCOL      6
#define HTTP_COPY       7
#define HTTP_MOVE       8
#define HTTP_OPTIONS    9
#define HTTP_PROPFIND   10
#define HTTP_PROPPATCH  11
#define HTTP_LOCK       12
#define HTTP_UNLOCK     13
#define HTTP_PATCH      14
#define HTTP_TRACE      15

#define PARAM_HDR_TYPE  0
#define PARAM_VAR_TYPE  1
#define PARAM_MZ_TYPE   2

/**
 * FUNCTION:  creata match data
 * @method:   request method HTTP_GET | HTTP_HEAD | HTTP_POST | ...
 * @uri:      request uri eg. http://192.168.1.1/abc/def/?a=b&b=c中的 /abc/def/
 * @args:     request args, eg. a=b&c=d
 * @cookies:  cookie value, such as "a=b;b=c;c=d"
 * @is_copy:  0-传入的是地址,零拷贝； 1-函数内部对参数进行拷贝(Used for Java)
 * RETURN:    return waf data handler 
 **/
void * waf_data_create(
        match_data_t *method,
        match_data_t *uri,
        match_data_t *args,
        match_data_t *cookies,
        match_data_t *request_body);

/** 
 * FUNCTION: show waf data's message 
 * @waf_data: waf data 
 **/
void waf_data_show(void *waf_data);

/** 
 * FUNCTION: destroy waf data 
 * @waf_data: waf data 
 **/
void waf_data_destroy(void *waf_data);

/** 
 * FUNCTION: add param to waf data 
 * @waf_data: waf data;
 * @param_type: PARAM_HDR_TYPE | PARAM_VAR_TYPE
 * @key_data: key data
 * @value_data: value data
 * RETURN:  WAF_MATCH_OK-add success;  WAF_MATCH_ERR-add failed;
 **/
int waf_data_add_param(void *waf_data, int type, match_data_t *key, match_data_t *value);

/* FUNCTION: 添加自定义匹配域映射 */
int waf_add_mz_mapping(void *waf_handler, match_data_t *key, match_data_t *value);

/* FUNCTION: 获取语义分析返回结果 */
sa_result_t *waf_sa_result_get(void *waf_data);

/* FUNCTION: return match result */
match_result_t *waf_match_result_get(void *waf_data);

void waf_match_data_free(match_data_t *m);

match_data_t * waf_match_data_alloc( unsigned char *data, size_t dlen, int is_copy, int init_result, int self_clone);

char * waf_get_non_default_mz(void *waf, char *out, size_t olen);

/*============================ USE DEAFULT CONFIG API =========================*/

/* FUNCTION: 初始化默认匹配域映射
 * @waf: create by waf_init, used in init 
 * RETURN: WAF_MATCH_ERR | WAF_MATCH_OK
 * */
int waf_init_mz_mapping_default(void *waf);

/* FUNCTION: Create default waf_data 
 * @have_body: r->headers_in.content_length_n > 0 ? 1 : 0
 * @method:  HTTP_GET | HTTP_POST ...
 * RETURN: succ: waf data ptr; failed: null
 **/
void * waf_data_create_default(
        int have_body,
        match_data_t *method,
        match_data_t *uri,
        match_data_t *args,
        match_data_t *cookies,
        match_data_t *request_body,
        match_data_t *request_uri,
        match_data_t *user_agent,
        match_data_t *referer,
        match_data_t *url);

/* FUNCTION: use by body phase, set request_body or response_body 
 * @data: waf_data
 * @body_type: WAF_BODY_TYPE_REQ | WAF_BODY_TYPE_RESP
 * @body: body match data 
 * RETURN: WAF_MATC_OK | WAF_MATCH_ERROR
 * */
int waf_data_set_body_default(void *waf_data, waf_phase_e phase, match_data_t *body);

/* FUNCTION: check for hit 
 * @waf_data: create by waf_data_create_default
 * RETURN: null: not hit; not null: hit 
 * */
policy_result_t * waf_policy_result_is_hit(void *waf_data);

/**FUNCTION: alloc match data 
 * @data: data
 * @dlen: data length
 * @self_clone: 0-free outside; 1-don't need free 
 *
 * RETURN: succ: match data; failed: null
 **/
#define WAF_MATCH_DATA_ALLOC_KEY(data, dlen) waf_match_data_alloc(data, dlen, 0, 0, 1)
#define WAF_MATCH_DATA_ALLOC_VALUE(data, dlen) waf_match_data_alloc(data, dlen, 0, 1, 1)

/* FUNCTION: show result message, used by debug */
char * waf_get_non_default_mz(void *waf_handler, char *out, size_t olen);

/** FUNCTION: get waf match zone count **/
int waf_get_waf_mz_count(void *waf_handler);

/* FUNCTION: check if mz is exist */
int waf_matcher_zones_find(void *waf_handler, const char *mz);

char *waf_get_commit_id();

int waf_dump(void *waf_handler);

void waf_data_get(void *waf_data, char *out, size_t olen);

const char *waf_get_rules_version(void *waf);

#endif

#ifdef __cplusplus
}
#endif


