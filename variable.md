

## 支持的nginx原生变量
### curl -H"Cookie: username=fanpf;passwd=123456" -H"Referer: www.baidu.com" 'http://10.0.2.15:8888/abc/.././././test?name=fanpf&id=11' -F "FILE=@./test.json"
+ "request:": POST /test?name=fanpf&id=11 HTTP/1.1
+ "request_body:": --------------------------b0c24a55384dfcad\x0D\x0AContent-Disposition: form-data; name=\x22FILE\x22; filename=\x22test.json\x22\x0D\x0AContent-Type: application/octet-stream\x0D\x0A\x0D\x0A{\x0A    \x22name\x22:\x22fanpf\x22,\x0A    \x22age\x22: 30\x0A}\x0A\x0D\x0A--------------------------b0c24a55384dfcad--\x0D\x0A
+ "request_method:": POST
+ "request_uri:": /test?name=fanpf&id=11
+ "args:": name=fanpf&id=11
+ "http_user_agent:": curl/7.68.0
+ "http_referer:": www.baidu.com
+ "http_cookie:": username=fanpf;passwd=123456
+ "uri:": /test
+ "arg_name:": fanpf

## nginx 变量说明
+ $arg_name
    - argument name in the request line
+ $args
    - arguments in the request line
+ $cookie_name
    - the name cookie
+ $document_uri
    - same as $uri
+ $host
    - in this order of precedence: host name from the request line, or host name from the “Host” request header field, or the server name matching a request
+ $query_string
    - same as $args
+ $request
    - full original request line
+ $request_body
    - request body
    - The variable’s value is made available in locations processed by the proxy_pass, fastcgi_pass, uwsgi_pass, and scgi_pass directives when the request body was read to a memory buffer.
+ $request_body_file
    name of a temporary file with the request body
At the end of processing, the file needs to be removed. To always write the request body to a file, client_body_in_file_only needs to be enabled. When the name of a temporary file is passed in a proxied request or in a request to a FastCGI/uwsgi/SCGI server, passing the request body should be disabled by the proxy_pass_request_body off, fastcgi_pass_request_body off, uwsgi_pass_request_body off, or scgi_pass_request_body off directives, respectively.
+ $request_filename
    - file path for the current request, based on the root or alias directives, and the request URI
+ $request_id
    - unique request identifier generated from 16 random bytes, in hexadecimal (1.11.0)
+ $request_method
    - request method, usually “GET” or “POST”
+ $request_uri
    full original request URI (with arguments)
+ $scheme
    request scheme, “http” or “https”
+ $uri
    - current URI in request, normalized
    - The value of $uri may change during request processing, e.g. when doing internal redirects, or when using index files.
