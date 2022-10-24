# CRProxy (Container Registry Proxy)

CRProxy is a generic image proxy

Add the prefix `cr.zsm.io/` to all places that need to use images

- [English](https://github.com/wzshiming/crproxy/blob/master/README.md)
- [简体中文](https://github.com/wzshiming/crproxy/blob/master/README_cn.md)

## cr.zsm.io

This is an experimental server and is not guaranteed to be stable,  
so you can deploy your own image proxy server if you need to.

[Refer to](https://github.com/wzshiming/crproxy/tree/master/examples/default)

## On Docker

Just add the prefix `cr.zsm.io/`

``` bash
docker pull cr.zsm.io/docker.io/library/busybox
```

## On Kubernetes

Just add the prefix `cr.zsm.io/`

``` yaml
image: cr.zsm.io/docker.io/library/busybox
```
