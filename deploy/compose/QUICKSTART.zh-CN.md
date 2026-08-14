# AOR 极简启动教程

适用于 Linux 单机开发和可信测试环境。

## 1. 准备环境

安装 Docker Engine、Docker Compose v2、GNU Make 和 OpenSSL。

## 2. 克隆并启动

```bash
git clone https://github.com/asdetycv1zzc/AOR.git
cd AOR
make compose-up
```

命令结束且所有服务显示为 `healthy` 后，打开：

```text
http://127.0.0.1:8090/ui/
```

## 3. 配置模型

进入 **模型设置**，填写所用模型提供商的 Base URL 和 API Key，保存后即可使用。

## 常用命令

```bash
# 查看服务状态
make compose-ps

# 停止服务并保留数据
docker compose --parallel 1 -f deploy/compose/docker-compose.yml --profile aor down
```

