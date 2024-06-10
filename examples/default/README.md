# 📢 部署须知

当前的部署形式其实只适用于小量使用的场景, 用的人多会很卡啊, 适用于大量使用的场景的代码是已经在项目里了还没文档描述（作者精力有限，欢迎大佬提交pr）

另外本文中显示的仓库地址：`kubesre.xyz`，只做本文演示使用，不保证其稳定和有效性。

## 开始部署

### 前提

- 准备一台访问网络畅通的服务器

  > 推荐腾讯云轻量服务器，区域地域选择亚洲离中国近的地方，最近618特惠，一个月的才26元 [点击直达](https://curl.qcloud.com/RW4e7hIf)

- 准备一个域名（无需备案）并做好 DNS 解析：添加两条解析记录 `@` 记录 和 `*` 记录到准备好的服务器的 IP

  > 域名推荐选择`xyz`结尾了，首年最低7元.
  >
  > 如果你想使用二级域名,以`cr.kubesre.xyz`举例，你可以将`cr`和`*.cr`解析到服务器ip.

- 安装好 docker 和 docker-compose 参考：[菜鸟教程](https://www.runoob.com/docker/centos-docker-install.html)

### 拉取代码

```
git clone https://github.com/wzshiming/crproxy.git
```

### 进入项目目录

```
cd crproxy/examples/default
```

### 修改gateway域名

vim start.sh 第五行

```
原：gateway=cr.zsm.io 
修改为：gateway=kubesre.xyz #改成你自己的域名
```

### 启动服务

```
./start.sh
```

> 如果出现了报错大概率是申请ssl证书时,ca机构检查到没有将域名解析到当前服务器导致的.
>
> 如果刚刚添加了域名解析,等解析生效后重新执行`./start.sh`即可

如果一切正常这时候你就可以通过添加前缀的方式拉取镜像了.

假如你的域名是：`kubesre.xyz`

**使用增加前缀拉取镜像，比如：**

**映射关系如下**

```
k8s.gcr.io/coredns/coredns:v1.8.6 => kubesre.xyz/k8s.gcr.io/coredns/coredns:v1.8.6
```

**拉取镜像**

```
docker pull kubesre.xyz/k8s.gcr.io/coredns/coredns:v1.8.6
```

📢 注意：**如果你想使用前缀替换的方式拉取镜像 (务必域名做好 `*` 解析到服务器)**
**映射关系如下**

```
k8s.gcr.io/coredns/coredns:v1.8.6 => k8s-gcr.kubesre.xyz/coredns/coredns:v1.8.6
```

那你就需要执行 `setup-alias.sh` 脚本添加 `k8s-gcr` 作为 `k8s.gcr.io` 别名 

### 添加别名

**设置环境变量**

```
GETEWAY=kubesre.xyz ##替换成自己的域名
```

> 第一个参数前缀替换的域名
> 第二个参数是源站的域名
> 第三个参数是在`start.sh`脚本里配置的网关域名

```
./setup-alias.sh k8s-gcr.${GETEWAY} k8s.gcr.io ${GETEWAY}
```

### 为别名申请证书

```
update-tls.sh k8s-gcr.${GETEWAY}
```

**重启一下nginx服务**

```
./reload.sh
```

不出意外这时候你就可以使用前缀替换方式拉取镜像了

**感受一下愉快的拉取镜像吧**

```
docker pull k8s-gcr.kubesre.xyz/coredns/coredns:v1.8.6
```

##  扩展

### 常用的镜像仓库

常用的镜像仓库一般有这些:

| 源站                    | 别名                   |
| ----------------------- | ---------------------- |
| cr.l5d.io               | l5d.kubesre.xyz        |
| docker.elastic.co       | elastic.kubesre.xyz    |
| docker.io               | docker.kubesre.xyz     |
| gcr.io                  | gcr.kubesre.xyz        |
| ghcr.io                 | ghcr.kubesre.xyz       |
| k8s.gcr.io              | k8s-gcr.kubesre.xyz    |
| registry.k8s.io         | k8s.kubesre.xyz        |
| mcr.microsoft.com       | mcr.kubesre.xyz        |
| nvcr.io                 | nvcr.kubesre.xyz       |
| quay.io                 | quay.kubesre.xyz       |
| registry.jujucharms.com | jujucharms.kubesre.xyz |

###  添加常用镜像仓库别名

**设置环境变量**

```bash
GETEWAY=kubesre.xyz ##替换成自己的域名
```

**添加别名**

```bash
./setup-alias.sh l5d.${GETEWAY} cr.l5d.io ${GETEWAY}
./setup-alias.sh elastic.${GETEWAY} docker.elastic.co ${GETEWAY}
./setup-alias.sh docker.${GETEWAY} docker.io ${GETEWAY}
./setup-alias.sh gcr.${GETEWAY} gcr.io ${GETEWAY}
./setup-alias.sh ghcr.${GETEWAY} ghcr.io ${GETEWAY}
./setup-alias.sh k8s-gcr.${GETEWAY} k8s.gcr.io ${GETEWAY}
./setup-alias.sh k8s.${GETEWAY} registry.k8s.io ${GETEWAY}
./setup-alias.sh mcr.${GETEWAY} mcr.microsoft.com ${GETEWAY}
./setup-alias.sh nvcr.${GETEWAY} nvcr.io ${GETEWAY}
./setup-alias.sh quay.${GETEWAY} quay.io ${GETEWAY}
./setup-alias.sh jujucharms.${GETEWAY} registry.jujucharms.com ${GETEWAY}
./setup-alias.sh rocks-canonical.${GETEWAY} rocks.canonical.com ${GETEWAY}
```

**给别名申请证书**

```bash
./update-tls.sh gcr.${GETEWAY}  
./update-tls.sh ghcr.${GETEWAY}         
./update-tls.sh k8s-gcr.${GETEWAY}      
./update-tls.sh k8s.${GETEWAY}
./update-tls.sh k8s.${GETEWAY}
./update-tls.sh mcr.${GETEWAY}  
./update-tls.sh nvcr.${GETEWAY}
./update-tls.sh quay.${GETEWAY}
./update-tls.sh jujucharms.${GETEWAY} 
./update-tls.sh rocks-canonical.${GETEWAY}  
```

最后重启下就可以了

```
./reload.sh
```
## 采用者列表
- kubesre.xyz [docker-registry-mirrors](https://github.com/kubesre/docker-registry-mirrors)
- m.daocloud.io [public-image-mirror](https://github.com/DaoCloud/public-image-mirror)
