# 部署为 systemd 服务


```shell
# 1. 复制二进制文件到系统目录
sudo cp /home/vagrant/bgo/bin/bgo /usr/local/bin/

# 2. 创建服务文件
sudo tee /etc/systemd/system/bgo-filter-dns.service << 'EOF'
[Unit]
Description=BGO DNS Filter XDP Service
Documentation=https://github.com/meimeitou/bgo
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bgo filter-dns -i enp24s0f0
Restart=on-failure
RestartSec=5
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bgo-filter-dns
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# 3. 重新加载 systemd
sudo systemctl daemon-reload

# 4. 启用开机启动
sudo systemctl enable bgo-filter-dns

# 5. 立即启动服务
sudo systemctl start bgo-filter-dns

# 6. 检查状态
sudo systemctl status bgo-filter-dns

# 7. 查看日志
sudo journalctl -u bgo-filter-dns -f
```