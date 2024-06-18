# 📢 部署须知
当前的部署形式其实只适用于小量使用的场景, 用的人多会很卡啊, 适用于大量使用的场景的代码是已经在项目里了还没文档描述（作者精力有限，欢迎大佬提交pr）

## 快速开始
### 前提
- 准备一台访问网络畅通的服务器
- 准备一个域名（无需备案）并做好 DNS 解析：添加两条解析记录 `@` 记录 和 `*` 记录到准备好的服务器的 IP
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
原：gateway=m.daocloud.io 
修改为：gateway=kubesre.xyz #改成你自己的域名
```
### 启动服务
```
./start.sh
```
如果一切正常这时候你就可以通过添加前缀的方式拉取镜像了

假如你的域名是：kubesre.xyz

**增加前缀 (推荐方式)。比如：**
```
k8s.gcr.io/coredns/coredns => kubesre.xyz/k8s.gcr.io/coredns/coredns
```
📢 注意：**如果你想使用前缀替换的方式拉取镜像 (务必域名做好 `*` 解析到服务器)**
如
```
k8s.gcr.io/coredns/coredns => k8s-gcr.kubesre.xyz/coredns/coredns
```
然后你就需要执行 setup-alias.sh 脚本添加 `k8s-gcr` 作为 `k8s.gcr.io` 别名 
### 添加别名
第一个参数前缀替换的域名
第一个参数是源站的域名
第三个参数是在**start.sh**脚本里配置的网关域名
```
./setup-alias.sh k8s-gcr.kubesre.xyz k8s.gcr.io kubesre.xyz
```
### 为别名申请证书
```
update-tls.sh k8s-gcr.kubesre.xyz
```
不出意外这时候你就可以使用前缀替换方式拉取镜像了

## 感受一下愉快的拉取镜像吧
```
docker pull k8s-gcr.kubesre.xyz/coredns/coredns:v1.8.6
```
## 采用者列表
- kubesre.xyz [docker-registry-mirrors](https://github.com/kubesre/docker-registry-mirrors)
- m.daocloud.io [public-image-mirror](https://github.com/DaoCloud/public-image-mirror)
