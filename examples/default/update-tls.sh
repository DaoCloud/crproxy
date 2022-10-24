#!/usr/bin/env bash

domain=${1:-}

if [[ -z "${domain}" ]]; then
    echo "domain is required"
    exit 1
fi

function cert_renew() {
    local domain=$1
    docker-compose exec gateway certbot --nginx -n --rsa-key-size 4096 --agree-tos --register-unsafely-without-email --domains "${domain}"
}

cert_renew "${domain}"
