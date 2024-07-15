# 📢 部署须知

当前的部署形式其实只适用于个人小量使用的场景

## 快速开始

### 前提
- 准备一台服务器, 需要确保 80 和 443 端口打开
- 准备一个域名并做好 DNS 解析到准备好的服务器的 IP
- 安装好 docker 和 docker-compose 参考：[菜鸟教程](https://www.runoob.com/docker/centos-docker-install.html)

### 启动

在服务器里新建一个文件 `docker-compose.yaml` 内容如下

``` yaml
version: '3'
services:
  crproxy:
    image: ghcr.io/daocloud/crproxy/crproxy:v0.9.1
    container_name: crproxy
    restart: unless-stopped
    ports:
    - 80:8080
    - 443:8080
    command: |
      --acme-cache-dir=/tmp/acme
      --acme-hosts=*
      --default-registry=docker.io
    tmpfs:
      - /tmp/acme
    
    # 非必须, 如果这台服务器无法畅通的达到你要的镜像仓库可以尝试配置 
    environment:
    - https_proxy=http://proxy:8080
    - http_proxy=http://proxy:8080
```

然后执行 `docker-compose up -d`


## 然后就能愉快的拉取镜像了

``` shell
docker pull 你的域名/hello-world
```

也可以添加到 /etc/docker/daemon.json

``` json
{
  "registry-mirrors": [
    "https://你的域名"
  ]
}
```

``` shell
docker pull hello-world
```
