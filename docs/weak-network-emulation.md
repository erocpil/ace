# 基于 Network Namespace 的弱网仿真环境

## 1. 目标与范围

本文说明如何在单台 Linux 主机上构建点对点弱网环境。客户端和服务端分别
运行在独立的 network namespace 中，通过一对 veth 接口通信。两个方向均
配置以下网络条件：

- 出口带宽上限：10 Mbps；
- 随机丢包率：5%。

该环境适用于网络应用的功能验证、故障恢复测试和性能基线测试。配置仅影响
两个 namespace 内的测试流量，不改变宿主机现有接口的队列规则。

## 2. 网络拓扑

```text
            netns-client namespace                       netns-server namespace
  +----------------------------------------+   +----------------------------------------+
  |                                        |   |                                        |
  |  client process                        |   |                         server process |
  |        |                               |   |                               ^        |
  |        v                               |   |                               |        |
  |  HTB class 1:10                        |   |                        HTB class 1:10   |
  |  rate 10 Mbps / ceil 10 Mbps           |   |           rate 10 Mbps / ceil 10 Mbps |
  |        |                               |   |                               ^        |
  |        v                               |   |                               |        |
  |  netem loss 5%                         |   |                       netem loss 5%    |
  |        |                               |   |                               ^        |
  |        v                               |   |                               |        |
  |  eth0  10.200.0.1/30  <---------------+---+--------------->  10.200.0.2/30  eth0  |
  |                                        |   |                                        |
  +----------------------------------------+   +----------------------------------------+
                    veth pair (both endpoints renamed to eth0)

        client -> server: maximum 10 Mbps, random loss 5%
        server -> client: maximum 10 Mbps, random loss 5%
```

两个接口位于 `10.200.0.0/30` 直连网段。配置接口地址后，内核会自动生成直连
路由，因此该拓扑不需要默认路由、IP 转发或 NAT。

两个方向分别限速，互不共享带宽。全双工并发传输时，两个方向可以各使用
10 Mbps；此时链路的双向发送速率合计最多约为 20 Mbps。

## 3. 流量控制模型

### 3.1 tc 与 qdisc

`tc`（Traffic Control）是 `iproute2` 提供的流量控制配置工具。它用于管理
Linux 内核中的队列规则（queueing discipline，简称 qdisc）、流量类别和过滤
器。本文只配置接口的出口方向：

```text
tc 配置工具
  +-- root qdisc: HTB
        +-- class 1:10: 10 Mbps
              +-- leaf qdisc: netem, loss 5%
```

qdisc 是内核中的实际排队机制，`tc` 负责创建、修改和查看这些对象。veth 的
一端发出的数据由该端的出口 qdisc 处理；接收端不会再次执行同一方向的出口
规则。因此，需要在两个 namespace 中分别配置规则，才能形成对称弱网环境。

### 3.2 HTB

HTB（Hierarchical Token Bucket）是支持分层分类的带宽整形 qdisc。本文只
建立一个流量类别，所有出口流量均进入 `1:10`：

- `rate 10mbit`：该类别的保证速率；
- `ceil 10mbit`：该类别允许达到的最高速率；
- `burst 32k`：令牌桶允许的短时突发量；
- `default 10`：未被过滤器显式分类的流量进入类别 `1:10`。

`rate` 和 `ceil` 均设置为 10 Mbps，因此该类别不能通过借用空闲带宽突破
10 Mbps 上限。当前拓扑只有一个类别，使用 HTB 的目的主要是将带宽整形与
netem 的损伤模型分离，便于后续扩展多种流量类别。

### 3.3 netem

netem（Network Emulator）用于模拟丢包、延迟、抖动、重复和乱序等网络
现象。本文将 netem 作为 HTB 类别 `1:10` 的叶子 qdisc，并配置
`loss random 5%`。

5% 是每个出口方向独立的随机丢包概率，不表示固定每 20 个包丢弃 1 个包。
单次测试结果会围绕 5% 波动，测试时间和数据包数量增加后，统计值通常会
逐渐接近配置值。

如果将一次交互简化为两个独立数据包（请求和响应各一个），并且不考虑协议
重传，则至少一个数据包丢失的概率为：

```text
1 - (1 - 0.05) * (1 - 0.05) = 9.75%
```

该数值是两个独立方向的组合概率，不是单向链路的丢包率。

## 4. 前置条件

执行配置需要 root 权限。系统需要提供以下组件：

- 支持 network namespace 和 veth 的 Linux 内核；
- `iproute2`，提供 `ip` 和 `tc`；
- `iperf3`，用于验证带宽和丢包率；
- HTB 和 netem 内核模块或内建支持。

Debian/Ubuntu 安装命令如下：

```bash
sudo apt-get update
sudo apt-get install -y iproute2 iperf3
```

## 5. 创建隔离网络

以下命令应在宿主机执行。若同名 namespace 已存在，应先按照第 9 节清理
旧环境。

```bash
# 创建客户端和服务端 network namespace。
sudo ip netns add netns-client
sudo ip netns add netns-server

# 创建 veth pair，并将两端分别移入对应的 namespace。
sudo ip link add veth-client type veth peer name veth-server
sudo ip link set veth-client netns netns-client
sudo ip link set veth-server netns netns-server

# 两端处于不同的 namespace，可以使用相同的接口名。
sudo ip -n netns-client link set veth-client name eth0
sudo ip -n netns-server link set veth-server name eth0

# 配置接口地址。
sudo ip -n netns-client address add 10.200.0.1/30 dev eth0
sudo ip -n netns-server address add 10.200.0.2/30 dev eth0

# 启用 loopback 和 veth 接口。
sudo ip -n netns-client link set lo up
sudo ip -n netns-server link set lo up
sudo ip -n netns-client link set eth0 up
sudo ip -n netns-server link set eth0 up
```

检查接口和路由：

```bash
sudo ip -n netns-client address show dev eth0
sudo ip -n netns-server address show dev eth0
sudo ip -n netns-client route show
sudo ip -n netns-server route show
```

两个 namespace 中应分别出现如下直连路由：

```text
# netns-client
10.200.0.0/30 dev eth0 proto kernel scope link src 10.200.0.1

# netns-server
10.200.0.0/30 dev eth0 proto kernel scope link src 10.200.0.2
```

## 6. 配置双向弱网规则

### 6.1 客户端出口

```bash
sudo ip netns exec netns-client \
  tc qdisc add dev eth0 root handle 1: htb default 10

sudo ip netns exec netns-client \
  tc class add dev eth0 parent 1: classid 1:10 \
  htb rate 10mbit ceil 10mbit burst 32k

sudo ip netns exec netns-client \
  tc qdisc add dev eth0 parent 1:10 handle 10: \
  netem limit 1000 loss random 5%
```

### 6.2 服务端出口

```bash
sudo ip netns exec netns-server \
  tc qdisc add dev eth0 root handle 1: htb default 10

sudo ip netns exec netns-server \
  tc class add dev eth0 parent 1: classid 1:10 \
  htb rate 10mbit ceil 10mbit burst 32k

sudo ip netns exec netns-server \
  tc qdisc add dev eth0 parent 1:10 handle 10: \
  netem limit 1000 loss random 5%
```

其中，`limit 1000` 将 netem 队列上限设为 1000 个包。在发送负载持续超过
10 Mbps 时，队列达到上限后可能产生额外丢包；该部分丢包不属于配置的 5%
随机丢包。

### 6.3 检查配置

```bash
sudo ip netns exec netns-client tc qdisc show dev eth0
sudo ip netns exec netns-client tc class show dev eth0
sudo ip netns exec netns-server tc qdisc show dev eth0
sudo ip netns exec netns-server tc class show dev eth0
```

执行连通性检查：

```bash
sudo ip netns exec netns-client ping -c 20 10.200.0.2
```

少量 ICMP 数据包仅用于确认地址和路由配置，不适合用于评估 5% 丢包率。

## 7. 使用 iperf3 验证

在终端 1 启动服务端，并在后续测试期间保持运行：

```bash
sudo ip netns exec netns-server \
  iperf3 -s -B 10.200.0.2
```

以下客户端命令在终端 2 执行。

### 7.1 TCP 吞吐测试

客户端向服务端发送：

```bash
sudo ip netns exec netns-client \
  iperf3 -c 10.200.0.2 -B 10.200.0.1 -t 30
```

使用 `-R` 参数测试服务端向客户端发送：

```bash
sudo ip netns exec netns-client \
  iperf3 -c 10.200.0.2 -B 10.200.0.1 -t 30 -R
```

TCP 会因丢包触发重传和拥塞控制，应用层吞吐可能显著低于 10 Mbps。TCP
测试用于观察弱网条件下的协议行为，不应作为带宽整形精度的唯一依据。

### 7.2 UDP 丢包率测试

验证 netem 随机丢包时，应将发送速率设置为低于 HTB 上限的值，以避免队列
拥塞引入额外丢包。以下测试采用 8 Mbps、1200 字节数据报并持续 60 秒。

客户端向服务端发送：

```bash
sudo ip netns exec netns-client \
  iperf3 -c 10.200.0.2 -B 10.200.0.1 \
  -u -b 8M -l 1200 -t 60
```

服务端向客户端发送：

```bash
sudo ip netns exec netns-client \
  iperf3 -c 10.200.0.2 -B 10.200.0.1 \
  -u -b 8M -l 1200 -t 60 -R
```

应以接收端报告的 `Lost/Total Datagrams` 和丢包百分比为准。两个方向的长期
统计结果均应接近 5%，但单次结果不要求精确等于 5%。

### 7.3 UDP 带宽上限测试

将发送负载提高到 20 Mbps，用于确认 HTB 的 10 Mbps 上限：

```bash
# 客户端向服务端发送。
sudo ip netns exec netns-client \
  iperf3 -c 10.200.0.2 -B 10.200.0.1 \
  -u -b 20M -l 1200 -t 30

# 服务端向客户端发送。
sudo ip netns exec netns-client \
  iperf3 -c 10.200.0.2 -B 10.200.0.1 \
  -u -b 20M -l 1200 -t 30 -R
```

接收端统计不会精确等于 10 Mbps，原因包括 netem 随机丢包、协议开销和队列
溢出。HTB 类别统计中的发送速率和累计字节数更适合用于判断整形规则是否
生效。

## 8. 查看运行统计

在测试前后执行以下命令：

```bash
sudo ip netns exec netns-client tc -s qdisc show dev eth0
sudo ip netns exec netns-client tc -s class show dev eth0
sudo ip netns exec netns-server tc -s qdisc show dev eth0
sudo ip netns exec netns-server tc -s class show dev eth0
```

重点关注以下字段：

- `Sent`：qdisc 处理的累计字节数和数据包数；
- `dropped`：netem 随机丢包与队列溢出产生的累计丢包；
- `overlimits`：流量超过整形速率、需要延后发送的次数；
- `backlog`：当前队列中等待发送的数据量。

`overlimits` 表示整形器执行了限速，不等同于丢包。持续存在较大 `backlog`
通常表示发送负载高于配置带宽。

## 9. 清理环境

首先停止 namespace 中运行的测试进程，然后在宿主机执行：

```bash
sudo ip netns del netns-client
sudo ip netns del netns-server
```

删除 namespace 时，其中的接口、qdisc 和路由会同时删除。veth 任意一端被
删除后，其对端也会由内核移除，无需单独执行 `tc qdisc del` 或
`ip link del`。

如需确认清理结果，可执行：

```bash
ip netns list
```
