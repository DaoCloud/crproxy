# 本地版

- 旨在方便快捷
- nas部署即可、无需vps、无需公网、域名可选

### docker运行crproxy
```
docker run -d --name crproxy \
    -p 8080:8080 \
    -e HTTPS_PROXY=http://代理ip:代理port \
    ghcr.io/wzshiming/crproxy/crproxy:v0.1.0
```
`如crproxy所在宿主机全局代理，则无需添加-e HTTPS_PROXY环境变量`

### nginx配置（可省略、6be7957c合并可删除该步骤）
npm或nginx均可、反代crproxy
```
location /v2/ {
    if ($request_uri !~* \.io) {
        rewrite ^/v2/(.*)$ /v2/docker.io/$1 break;
    }
    proxy_pass http://crproxyip:crproxyport;
}
```

### 配置daemon.json
```
mkdir -p /etc/docker
tee /etc/docker/daemon.json <<-'EOF'
{
    "insecure-registries" : ["nginx_ip:nginx_port"],
    "registry-mirrors": [
        "http(s)://nginx_ip:nginx_port"
    ]
}
EOF
```
`nginx_ip:nginx_port按照实际情况填写，域名和ip均可。`

`这里可直接使用crproxy的ip和端口，区别在于nginx反代可以不用在docker pull的时候指定docker.io镜像仓库。`

### 重启docker
```
systemctl daemon-reload
systemctl restart docker
```