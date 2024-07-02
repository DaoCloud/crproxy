# CRProxy (Container Registry Proxy)

CRProxy is a generic image proxy

Add the prefix `m.daocloud.io/` to all places that need to use images

- [English](https://github.com/wzshiming/crproxy/blob/master/README.md)
- [简体中文](https://github.com/wzshiming/crproxy/blob/master/README_cn.md)

## m.daocloud.io

you can deploy your own image proxy server if you need to.

[Refer to](https://github.com/wzshiming/crproxy/tree/master/examples/default)

## crproxy + registry(pull through cache mode)

- for organizations and companies which need to serve big clusters
- [container-image-mirror](https://blog.geekcity.tech/articles/kubernetes/argocd/container-image-mirror/)
    * deploy into k8s with argocd
    * storage with pvc, s3(minio/oss compatible)
    * bind ssl with cert-manager and ingress

## On Docker

Just add the prefix `m.daocloud.io/`

``` bash
docker pull m.daocloud.io/docker.io/library/busybox
```

## On Kubernetes

Just add the prefix `m.daocloud.io/`

``` yaml
image: m.daocloud.io/docker.io/library/busybox
```
