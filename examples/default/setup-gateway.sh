#!/usr/bin/env bash

domain=${1:-}

if [[ -z "${domain}" ]]; then
    echo "domain is required"
    exit 1
fi

endpoint=${2:-}

if [[ -z "${endpoint}" ]]; then
    echo "endpoint is required"
    exit 1
fi

function gen() {
    local domain=$1
    local endpoint=$2
    cat <<EOF
server {
    listen 80;
    server_name ${domain};
    server_tokens off;

    access_log  /var/log/nginx/${domain}.access.log  main;

    proxy_set_header  Host              \$http_host;   # required for docker client's sake
    proxy_set_header  X-Real-IP         \$remote_addr; # pass on real client's IP
    proxy_set_header  X-Forwarded-For   \$proxy_add_x_forwarded_for;
    proxy_set_header  X-Forwarded-Proto \$scheme;
    proxy_read_timeout                  900;
    proxy_send_timeout                  300;

    proxy_request_buffering             off; # (see issue #2292 - https://github.com/moby/moby/issues/2292)

    # disable any limits to avoid HTTP 413 for large image uploads
    client_max_body_size 0;

    # required to avoid HTTP 411: see Issue #1486 (https://github.com/moby/moby/issues/1486)
    chunked_transfer_encoding on;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    #error_page  404              /404.html;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }

    # # (Options) docker.io uses aliyuncs mirror 😄
    # location ~ ^/v2/docker.io/(.+)\$  {
    #    return 302 https://public.mirror.aliyuncs.com/v2/\$1;
    # }

    # Read only, Reject all writes !!!!!!!!!!
    if (\$request_method !~* GET|HEAD) {
        return 403;
    }

    location /v2/ {
        proxy_pass http://${endpoint};
    }
}
EOF
}

conf="nginx/gateway-${domain}.conf"

if [[ ! -f "${conf}" ]]; then
  mkdir -p nginx
  gen "${domain}" "${endpoint}" >"nginx/gateway-${domain}.conf"
fi
