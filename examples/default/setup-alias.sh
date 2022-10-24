#!/usr/bin/env bash

domain=${1:-}

if [[ -z "${domain}" ]]; then
    echo "domain is required"
    exit 1
fi

origin=${2:-}

if [[ -z "${origin}" ]]; then
    echo "origin is required"
    exit 1
fi

gateway=${3:-}

if [[ -z "${gateway}" ]]; then
    echo "gateway is required"
    exit 1
fi

function gen() {
    local domain=$1
    local origin=$2
    local gateway=$3
    cat <<EOF
server {
    listen 80;
    server_name ${domain};
    server_tokens off;

    access_log  /var/log/nginx/${domain}.access.log  main;

    location = /v2/ {
        default_type "application/json; charset=utf-8";
        return 200 "{}";
    }

    location ~ ^/v2/(.+)\$ {
        return 301 https://${gateway}/v2/${origin}/\$1;
    }
}
EOF
}

conf="nginx/alias-${domain}.conf"

if [ ! -f "${conf}" ]; then
  mkdir -p nginx
  gen "${domain}" "${origin}" "${gateway}" >"${conf}"
fi
