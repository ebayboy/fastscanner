package scanner

//var m1 map[int]int = map[int]int{1: 100, 2: 200}
var data_mz_map map[string]string = map[string]string{
	"$request_uri":     "request_uri",
	"$http_referer":    "Referer",
	"$http_user_agent": "User-Agent",
	"$request_body":    "request_body",
}

/*
#define WAF_VAR_KEY_URL             "url"
#define WAF_VAR_KEY_REQUEST_URI     "request_uri"
#define WAF_HDR_KEY_USER_AGENT      "User-Agent"
#define WAF_HDR_KEY_REFERER         "Referer"
#define WAF_VAR_RESPONSE_BODY       "response_body"

#define WAF_MZ_URI                  "$uri"
#define WAF_MZ_ARGS                 "$args"
#define WAF_MZ_HTTP_URL             "$url"
#define WAF_MZ_REQUEST_URI          "$request_uri"
#define WAF_MZ_REQUEST_BODY         "$request_body"
#define WAF_MZ_HTTP_REFERER         "$http_referer"
#define WAF_MZ_HTTP_USER_AGENT      "$http_user_agent"
#define WAF_MZ_RESPONSE_BODY        "$response_body"

#define WAF_MZ_HTTP_COOKIE          "$http_cookie"
#define WAF_MZ_REQUEST_HEADERS      "$request_headers"
#define WAF_MZ_RESPONSE_HEADERS     "$response_headers"
#define WAF_MZ_U_RESPONSE_HEADERS   "$u_response_headers"

#define WAF_MZ_U_URI                "$u_uri"
#define WAF_MZ_U_ARGS               "$u_args"
#define WAF_MZ_U_ARGS_KV            "$U_ARGS"
#define WAF_MZ_U_REQUEST_URI        "$u_request_uri"
#define WAF_MZ_U_REQUEST_BODY       "$u_request_body"
#define WAF_MZ_U_HTTP_REFERER       "$u_http_referer"
#define WAF_MZ_U_HTTP_USER_AGENT    "$u_http_user_agent"
#define WAF_MZ_U_HTTP_URL           "$u_url"
#define WAF_MZ_U_HTTP_COOKIE        "$u_http_cookie"
#define WAF_MZ_U_REQUEST_HEADERS    "$u_request_headers"
#define WAF_MZ_U_REQUEST_HEADERS_VAL "$U_REQUEST_HEADERS"
#define WAF_MZ_U_RESPONSE_BODY      "$u_response_body"
#define WAF_MZ_U_REQUEST_METHOD     "$u_request_method"
#define WAF_MZ_U_REQUEST_URI_PATH   "$u_request_uri_path"

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
*/
