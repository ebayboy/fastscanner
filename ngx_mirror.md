## ngx_http_mirror_module 默认开启
+ nginx mirror模块: 只能镜像，镜像流量的block不会到真正后端的流量产生影响(可用于测试及灰度, 不能用于waf阻断)
+ fasthttp代码修改
/*
//For ngx mirror
//X-Real-IP
x_real_ip := ctx.Request.Header.Peek("X-Real-IP")
if len(x_real_ip) > 0 {
distCtx.Data["x_real_ip"] = x_real_ip
}

//Host
host := ctx.Request.Header.Peek("Host")
if len(host) > 0 {
distCtx.Data["host"] = x_real_ip
}

//X-Original-URI
request_uri := ctx.Request.Header.Peek("X-Original-URI")
if len(request_uri) > 0 {
distCtx.Data["request_uri"] = request_uri
}

 + nginx配置:https://nginx.org/en/docs/http/ngx_http_mirror_module.html#mirror
    ¦   location / {
    ¦   ¦   mirror /mirror;
    ¦   ¦   mirror_request_body on;
    ¦   ¦   #mirror off;
    ¦   ¦   proxy_pass   http://tomcat;
    ¦   }

    ¦   location /mirror {
    ¦   ¦   internal;
    ¦   ¦   #proxy_pass http://log_backend;  #for log
    ¦   ¦   #proxy_pass_request_body off;
    ¦   ¦   proxy_set_header Host $host;
    ¦   ¦   proxy_set_header X-Real-IP $remote_addr;
    ¦   ¦   proxy_set_header X-Original-URI $request_uri;
    ¦   ¦   proxy_pass http://unix:/tmp/fasthttp_hyperscan.sock;
    ¦   }

