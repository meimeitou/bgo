# 测试

## 功能测试

```shell
# 本机 192.168.63.10
# 机器1 192.168.63.20
# 机器2 192.168.63.30
# 启动防火墙服务器
sudo ./bin/bgo firewall-server start --interface enp0s8

# 启用 LVS 功能
sudo ./bin/bgo firewall-lvs enable

# 添加防火墙规则
sudo ./bin/bgo firewall-lvs add-dnat --vip 192.168.63.100 --vport 80 --rip 192.168.63.20 --rport 8080 --protocol tcp
# 网卡添加ip地址
sudo ip addr add 192.168.63.100/24 dev enp0s8
# 删除ip: sudo ip addr del 192.168.63.100/24 dev enp0s8

sudo tcpdump -i enp0s8 -nn -X 'dst 192.168.63.100 and tcp and dst port 80' 
```