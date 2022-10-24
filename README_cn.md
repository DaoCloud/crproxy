# CRProxy (Container Registry Proxy)

CRProxy 是一个通用的 Image 代理

在所有需要使用镜像的地方加上前缀 `cr.zsm.io/`

- [English](https://github.com/wzshiming/crproxy/blob/master/README.md)
- [简体中文](https://github.com/wzshiming/crproxy/blob/master/README_cn.md)

## cr.zsm.io

这是一个实验服务器并不保证一定稳定可靠,  
如有需要您可以部署自己的镜像代理服务器

[参考](https://github.com/wzshiming/crproxy/tree/master/examples/default)

## On Docker

只需要添加前缀 `cr.zsm.io/`

``` bash
docker pull cr.zsm.io/docker.io/library/busybox
```

## On Kubernetes

只需要添加前缀 `cr.zsm.io/`

``` yaml
image: cr.zsm.io/docker.io/library/busybox
```
