# CRProxy (Container Registry Proxy)

CRProxy 是一个通用的 Image 代理

在所有需要使用镜像的地方加上前缀 `m.daocloud.io/`

- [English](https://github.com/wzshiming/crproxy/blob/master/README.md)
- [简体中文](https://github.com/wzshiming/crproxy/blob/master/README_cn.md)

## m.daocloud.io

如有需要您可以部署自己的镜像代理服务器

[参考](https://github.com/wzshiming/crproxy/tree/master/examples/default)

## On Docker

只需要添加前缀 `m.daocloud.io/`

``` bash
docker pull m.daocloud.io/docker.io/library/busybox
```

## On Kubernetes

只需要添加前缀 `m.daocloud.io/`

``` yaml
image: m.daocloud.io/docker.io/library/busybox
```
