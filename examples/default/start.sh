#!/usr/bin/env bash

docker-compose up -d

gateway=m.daocloud.io

declare -A mapping=()

#./setup-gateway.sh "${gateway}" "registry:5000"
./setup-gateway.sh "${gateway}" "crproxy:8080"
./update-tls.sh "${gateway}"

for key in ${!mapping[*]}; do
  ./setup-alias.sh "${key}" "${mapping[$key]}" "${gateway}"
  ./update-tls.sh "${key}"
done
