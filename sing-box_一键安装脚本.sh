#!/bin/bash

################################入口################################
main() {
    home
}
################################主菜单################################
home() {
    clear
    echo "=================================================================="
    echo -e "\t\tLinux | 一键搭建脚本"
    echo -e "\t\tPowered by www.herozmy.com 2023"
    echo -e "\t\\n"
    echo -e "温馨提示：\n本脚本推荐使用ububtu22.04环境，其他环境未经验证，仅供个人使用"
    echo -e "本脚本仅适用于学习与研究等个人用途，请勿用于任何违反国家法律的活动！"
    echo "=================================================================="
    read -p "按Enter键继续~" -r
    sleep 1

    choose_singbox
}
################################更新相关依赖################################
apt_update_upgrade() {
    echo -e "系统更新"
    sleep 1
    apt update && apt -y upgrade || { echo "更新失败！退出脚本"; exit 1; }
    apt install curl wget tar gawk sed cron unzip nano -y
}
################################选择安装################################
choose_singbox() {
echo "欢迎使用脚本安装程序"
echo "请选择要安装的版本："
echo "1. 编译官方sing-box Core/升级"
echo "2. P版sing-box Core并配置"
echo "3. Mosdns V5,配合上面的sibg-box安装配置  备注:单独新开lxc或者vm运行"
echo "4. hysteria2 回家"
echo "5. clash.meta旁路由"
echo "6. easymosdns"
read choice
case $choice in
    1)
        echo "开始安装官方Singbox核心"
        apt_update_upgrade
        install_singbox
        install_service
        customize_settings
        install_tproxy
        install_sing_box_over
        ;;
    2)
        echo "开始安装P核sing-box核心"
        apt_update_upgrade
        install_p_singbox
        install_service
        customize_p_settings
        modify_dns_stub_listener
        install_tproxy
        install_p_sing_box_over
        ;;
    3)
        echo "Mosdns安装"
        apt_update_upgrade
        install_mosdns
        ;;
    4)
        echo "开始生成回家配置"
        install_home
        ;;
    5)
        echo "Clash.meta搭建脚本(未完成)"
        install_home
        ;;
    6)
        echo "Easymosdns(未完成)"
        install_home
        ;;
    *)
        echo "无效的选项，请重新运行脚本并选择有效的选项."
        ;;
esac
}
################################编译 Sing-Box 的最新版本################################
install_singbox() {
    echo -e "编译Sing-Box 最新版本"
    sleep 1
    apt -y install curl git build-essential libssl-dev libevent-dev zlib1g-dev gcc-mingw-w64
    echo -e "开始编译Sing-Box 最新版本"
    rm -rf /root/go/bin/*
    Go_Version=$(curl https://github.com/golang/go/tags | grep '/releases/tag/go' | head -n 1 | gawk -F/ '{print $6}' | gawk -F\" '{print $1}')
  # 判断 CPU 架构
if [[ $(uname -m) == "aarch64" ]]; then
    arch="arm64"
elif [[ $(uname -m) == "x86_64" ]]; then
    arch="amd64"
else
    arch="未知"
    exit 0
fi
echo "系统架构是：$arch"

    wget -O ${Go_Version}.linux-$arch.tar.gz https://go.dev/dl/${Go_Version}.linux-$arch.tar.gz
    tar -C /usr/local -xzf ${Go_Version}.linux-$arch.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
    source /etc/profile.d/golang.sh
    if ! go install -v -tags with_quic,with_grpc,with_dhcp,with_wireguard,with_ech,with_utls,with_reality_server,with_clash_api,with_gvisor,with_v2ray_api,with_lwip,with_acme github.com/sagernet/sing-box/cmd/sing-box@latest; then
        echo -e "Sing-Box 编译失败！退出脚本"
        exit 1
    fi
    echo -e "编译完成，开始安装"
    sleep 1
    # 检查是否存在旧版本的 sing-box
    if [ -f "/usr/local/bin/sing-box" ]; then
        echo "检测到已安装的 sing-box"
        read -p "是否替换升级？(y/n): " replace_confirm
        if [ "$replace_confirm" = "y" ]; then
            echo "正在替换升级 sing-box"
            cp "$(go env GOPATH)/bin/sing-box" /usr/local/bin/
echo "=================================================================="
echo -e "\t\t\tSing-Box 内核升级完毕"
echo -e "\t\t\tPowered by www.herozmy.com 2024"
echo -e "\n"
echo -e "温馨提示:\n本脚本仅在 LXC ubuntu22.04 环境下测试，其他环境未经验证，仅供个人使用"
echo -e "本脚本仅适用于学习与研究等个人用途，请勿用于任何违反国家法律的活动！"
echo "=================================================================="
            exit 0  # 替换完成后停止脚本运行
        else
            echo "用户取消了替换升级操作"
        fi
    else
        # 如果不存在旧版本，则直接安装新版本
        cp "$(go env GOPATH)/bin/sing-box" /usr/local/bin/
        echo -e "Sing-Box 安装完成"
    fi

    mkdir -p /etc/sing-box
    sleep 1
}
#####################################获取网卡################################
check_interfaces() {
    interfaces=$(ip -o link show | awk -F': ' '{print $2}')

    # 输出物理网卡名称
    for interface in $interfaces; do
        # 检查是否为物理网卡（不包含虚拟、回环等），并排除@符号及其后面的内容
        if [[ $interface =~ ^(en|eth).* ]]; then
            interface_name=$(echo "$interface" | awk -F'@' '{print $1}')  # 去掉@符号及其后面的内容
            echo "您的网卡是：$interface_name"
            valid_interfaces+=("$interface_name")  # 存储有效的网卡名称
        fi
    done
    # 提示用户选择
    read -p "脚本自行检测的是否是您要的网卡？(y/n): " confirm_interface
    if [ "$confirm_interface" = "y" ]; then
        selected_interface="$interface_name"
        echo "您选择的网卡是: $selected_interface"
    elif [ "$confirm_interface" = "n" ]; then
        read -p "请自行输入您的网卡名称: " selected_interface
        echo "您输入的网卡名称是: $selected_interface"
    else
        echo "无效的选择"
    fi
}
################################安装P核 sing-box################################
install_p_singbox() {
    echo -e "开始安装P_sing-box"
    sleep 1
      # 判断 CPU 架构
if [[ $(uname -m) == "aarch64" ]]; then
    arch="armv8"
elif [[ $(uname -m) == "x86_64" ]]; then
    arch="amd64"
else
    arch="未知"
    exit 0
fi
echo "系统架构是：$arch"

    #拉取github每日凌晨自动编译的核心
    wget -O sing-box-linux-$arch.tar.gz  https://raw.githubusercontent.com/52shell/herozmy-private/main/sing-box-puernya/sing-box-linux-$arch.tar.gz
    sleep 1
    echo -e "下载完成，开始安装"
    sleep 1
    tar -zxvf sing-box-linux-$arch.tar.gz
    if [ -f "/usr/local/bin/sing-box" ]; then
        echo "检测到已安装的 sing-box"
        read -p "是否替换升级？(y/n): " replace_confirm
        if [ "$replace_confirm" = "y" ]; then
            echo "正在替换升级 sing-box"
            mv  sing-box /usr/local/bin/
echo "=================================================================="
echo -e "\t\t\tSing-Box P核升级完毕"
echo -e "\t\t\tPowered by www.herozmy.com 2024"
echo -e "\n"
echo -e "温馨提示:\n本脚本仅在 LXC ubuntu22.04 环境下测试，其他环境未经验证，仅供个人使用"
echo -e "本脚本仅适用于学习与研究等个人用途，请勿用于任何违反国家法律的活动！"
echo "=================================================================="
       exit 0  # 替换完成后停止脚本运行
        else
            echo "用户取消了替换升级操作"
        fi
    else
        # 如果不存在旧版本，则直接安装新版本
        mv  sing-box /usr/local/bin/
        echo -e "Sing-Box 安装完成"
    fi
    mkdir -p /etc/sing-box
    sleep 1
}


################################回家配置脚本################################
install_home() {
    sleep 1 
    echo -e "hysteria2 回家 自签证书"
    echo -e "开始创建证书存放目录"
    mkdir -p /root/hysteria 
    echo -e "自签bing.com证书100年"
    openssl ecparam -genkey -name prime256v1 -out /root/hysteria/private.key && openssl req -new -x509 -days 36500 -key /root/hysteria/private.key -out /root/hysteria/cert.pem -subj "/CN=bing.com"
    while true; do
        # 提示用户输入域名
        read -p "请输入家庭DDNS域名: " domain
        # 检查域名格式是否正确
        if [[ $domain =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo "域名格式不正确，请重新输入"
        fi
    done  
    # 输入端口号
    while true; do
        read -p "请输入端口号: " hyport

        # 检查端口号是否为数字
        if [[ $hyport =~ ^[0-9]+$ ]]; then
            break
        else
            echo "端口号格式不正确，请重新输入"
        fi
    done
    read -p "请输入密码: " password
    echo "您输入的域名是: $domain"
    echo "您输入的端口号是: $hyport"
    echo "您输入的密码是: $password"
    sleep 2
    echo "开始生成配置文件"
    # 检查sb配置文件是否存在
    config_file="/etc/sing-box/config.json"
    if [ ! -f "$config_file" ]; then
        echo "错误：配置文件 $config_file 不存在"
        echo "请选择生成singbox或者P核singbox config.json脚本"
        
        exit 1
    fi   
    hy_config='{
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": '"${hyport}"',
      "sniff": true,
      "sniff_override_destination": false,
      "sniff_timeout": "100ms",
      "users": [
        {
          "password": "'"${password}"'"
        }
      ],
      "ignore_client_bandwidth": true,
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "/root/hysteria/cert.pem",
        "key_path": "/root/hysteria/private.key"
      }
    },
'
line_num=$(grep -n 'inbounds' /etc/sing-box/config.json | cut -d ":" -f 1)
# 如果找到了行号，则在其后面插入 JSON 字符串，否则不进行任何操作
if [ ! -z "$line_num" ]; then
    # 将文件分成两部分，然后在中间插入新的 JSON 字符串
    head -n "$line_num" /etc/sing-box/config.json > tmpfile
    echo "$hy_config" >> tmpfile
    tail -n +$(($line_num + 1)) /etc/sing-box/config.json >> tmpfile
    mv tmpfile /etc/sing-box/config.json
fi
    echo "HY2回家配置写入完成"
    echo "开始重启sing-box"
    systemctl restart sing-box
    echo "开始生成sing-box回家-手机配置"
    cat << EOF >  "/root/go_home.json"
{
    "log": {
        "level": "info",
        "timestamp": false
    },
    "dns": {
        "servers": [
            {
                "tag": "dns_proxy",
                "address": "tls://1.1.1.1:853",
                "strategy": "ipv4_only",
                "detour": "proxy"
            },
            {
                "tag": "dns_direct",
                "address": "https://223.5.5.5/dns-query",
                "strategy": "prefer_ipv6",
                "detour": "direct"
            },
            {
                "tag": "dns_resolver",
                "address": "223.5.5.5",
                "detour": "direct"
            },
            {
                "tag": "dns_success",
                "address": "rcode://success"
            },
            {
                "tag": "dns_refused",
                "address": "rcode://refused"
            },
            {
                "tag": "dns_fakeip",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "domain_suffix": [
                    "${domain}"         
                ],
                "server": "dns_direct",
                "disable_cache": true
            },
            {
                "rule_set": "geosite-cn",
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "dns_direct"
            },
            {
                "rule_set": "geosite-cn",
                "query_type": [
                    "CNAME"
                ],
                "server": "dns_direct"
            },      
            {
                "rule_set": "geosite-geolocation-!cn",
                "query_type": [
                    "A"          
                ],
                "server": "dns_fakeip"
            },
            {
                "rule_set": "geosite-geolocation-!cn",
                "query_type": [
                    "CNAME"
                ],
                "server": "dns_proxy"
            },
            {
                "query_type": [
                    "A",
                    "AAAA",
                    "CNAME"
                ],
                "invert": true,
                "server": "dns_refused",
                "disable_cache": true
            }
        ],
        "final": "dns_proxy",
        "independent_cache": true,
        "fakeip": {
            "enabled": true,
            "inet4_range": "198.18.0.0/15",
	    "inet6_range": "fc00::/18"
        }
    },
    "route": {
        "rule_set": [
            {
                "tag": "geosite-category-ads-all",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                "download_detour": "proxy"
            },
        {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                "download_detour": "proxy"
            },  
            {
                "tag": "geosite-geolocation-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
                "download_detour": "proxy"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                "download_detour": "proxy"
            }
        ],
        "rules": [
            {
                "protocol": "dns",
                "outbound": "dns-out"
            },
            {
            "ip_cidr": [   
                 "10.10.10.0/24"
               ],
                "outbound": "telecom_home" 
            },
            {
              "network": "udp",
              "port": 443,
              "outbound": "block"
           },
         {
             "domain_suffix": [ 
          ".cn"
		 ],
        "outbound": "direct"
        },
        {
      "domain_suffix": [ 
          "office365.com"
        ],
        "outbound": "direct"
        },
        {
        "domain_suffix": [
          "push.apple.com",
          "iphone-ld.apple.com",
          "lcdn-locator.apple.com",
          "lcdn-registration.apple.com"
        ],
        "outbound": "direct"
        },
        {
                "rule_set": "geosite-cn",
                "outbound": "direct"
            },
            {
                "rule_set": "geosite-geolocation-!cn",
                "outbound": "proxy"
            },
            {
                "rule_set": "geoip-cn",
                "outbound": "direct"
            },
            {
                "ip_is_private": true,
                "outbound": "direct"
            }
        ],
        "final": "proxy",
        "auto_detect_interface": true
    },
    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": "172.16.0.1/30",
            "inet6_address": "fd00::1/126",
            "mtu": 1400,
            "auto_route": true,
            "strict_route": true,
            "stack": "gvisor",
            "sniff": true,
            "sniff_override_destination": false
        }
    ],
    "outbounds": [
        {
            "tag":"proxy",
            "type":"selector",
            "outbounds":[
            "telecom_home"
          ]
        },
       {
         "type": "hysteria2",
         "server": "${domain}",       
         "server_port": ${hyport}, 
         "tag": "telecom_home", 
         "up_mbps": 50,
         "down_mbps": 500,
         "password": "${password}",
         "tls": {
         "enabled": true,
         "server_name": "bing.com",   
         "insecure": true,
         "alpn": [
          "h3"
            ]
          }
        },
     
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        },
        {
            "type": "dns",
            "tag": "dns-out"
        }
    ],
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "cache.db",
            "store_fakeip": true
        }
    }
}
EOF
    
    sleep 1
echo "=================================================================="
echo -e "\t\t\tSing-Box 回家配置生成完毕"
echo -e "\t\t\tPowered by www.herozmy.com 2024"
echo -e "\n"
echo -e "sing-box 回家配置生成路径为: /root/go_home.json\t\t请自行复制至 sing-box 客户端"
echo -e "温馨提示:\n本脚本仅在 LXC ubuntu22.04 环境下测试，其他环境未经验证，仅供个人使用"
echo -e "本脚本仅适用于学习与研究等个人用途，请勿用于任何违反国家法律的活动！"
echo "================================================================="
}

################################启动脚本################################
install_service() {
    echo -e "配置系统服务文件"
    sleep 1

    # 检查服务文件是否存在，如果不存在则创建
    sing_box_service_file="/etc/systemd/system/sing-box.service"
if [ ! -f "$sing_box_service_file" ]; then
    # 如果服务文件不存在，则创建
    cat << EOF > "$sing_box_service_file"
[Unit]
Description=Sing-Box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=1800s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    echo "sing-box服务创建完成"  
else
    # 如果服务文件已经存在，则给出警告
    echo "警告：sing-box服务文件已存在，无需创建"
fi 
    sleep 1
    systemctl daemon-reload
    
}
################################用户自定义设置################################
customize_settings() {
    echo "是否选择生成配置？(y/n)"
    echo "生成配置文件需要添加机场订阅，如自建vps请选择n"
    read choice
if [ "$choice" = "y" ]; then
    read -p "输入订阅连接：" suburl
    suburl="${suburl:-https://}"
    echo "已设置订阅连接地址：$suburl"
    install_config
    
elif [ "$choice" = "n" ]; then
    echo "请手动配置config.jaon."
fi
    
}

customize_p_settings() {
    echo "是否添加机场订阅？(y/n)"
    echo "生成配置文件需要添加机场订阅，如手动添加请输入n"
    read choice
if [ "$choice" = "y" ]; then
    echo "自定义设置（以下设置可直接回车使用默认值）"
    read -p "输入订阅连接：" suburl
    suburl="${suburl:-https://}"
    echo "已设置订阅连接地址：$suburl"
    install_p_config
    
elif [ "$choice" = "n" ]; then
    echo "请手动配置config.jaon."
else
    echo "无效的选项，请输入 'y' 或 'n'."
fi
}
################################开始创建config.json################################
install_config() {
    sub_host="https://sub-singbox.herozmy.com"   
    echo "请选择："
    echo "1. tproxy_fake_ip 规则多模式"
    echo "2. tproxy_fake_ip O大原版"
    read -p "请输入选项 [默认: 1]: " choice
    # 如果用户没有输入选择，则默认为1
    choice=${choice:-1}
    if [ $choice -eq 1 ]; then
        json_file="&file=https://file.herozmy.com/File/sing-box/config_json/tproxy.json"
    # 提示用户输入要替换的IP地址
    #read -p "请输入Mosdns地址: " mosdns
    # 使用sed命令替换config.json文件中的IP地址
    #sed -i "s/10.10.10.253/$mosdns/g" config.json
    elif [ $choice -eq 2 ]; then
        json_file="&file=https://file.herozmy.com/File/sing-box/config_json/fake-ip.json"
    else
        echo "无效的选择。"
        return 1
    fi
    curl -o config.json "${sub_host}/config/${suburl}${json_file}"    
    modify_dns_stub_listener
    # 检查下载是否成功
    if [ $? -eq 0 ]; then
        # 移动文件到目标位置
        mv config.json /etc/sing-box/config.json
        echo "Sing-box配置文件写入成功！"
    else
        echo "下载文件失败，请检查网络连接或者URL是否正确。"
    fi    
}
################################修改 DNSStubListener################################
modify_dns_stub_listener() {
    echo "关闭53端口监听"
    sed -i '/^#*DNSStubListener/s/#*DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
    systemctl restart systemd-resolved.service
}
################################写入P核配置文件################################
install_p_config() {
 mkdir  /etc/sing-box/providers
 echo '
{
    "log": {
        "disabled": false,
        "level": "info",
        "output": "/etc/sing-box/sing-box.log",
        "timestamp": true
    },
    "experimental": {
        "clash_api": {
            "external_controller": "0.0.0.0:9090",
            "external_ui": "/etc/sing-box/ui",
            "secret": "",
            "external_ui_download_url": "",
            "external_ui_download_detour": "",
            "default_mode": "rule"
        },
        "cache_file": {
            "enabled": true,
            "path": "/root/cache.db",
            "cache_id": "my_profile1",
            "store_fakeip": true
        }
    },
    "dns": {
        "servers": [
            {
                "tag": "nodedns",
                "address": "tls://223.5.5.5:853",
                "detour": "direct"
            },
            {
                "tag": "fakeipDNS",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "domain_suffix": [
                    "abc.com"
                ],
                "server": "nodedns",
                "disable_cache": true
            },
            {
                "inbound": "dns-in",
                "server": "fakeipDNS",
                "disable_cache": false,
                "rewrite_ttl": 1
            },
            {
                "outbound": "any",
                "server": "nodedns",
                "disable_cache": true
            }
        ],
        "fakeip": {
            "enabled": true,
            "inet4_range": "28.0.0.1/8"
        },
        "strategy": "prefer_ipv4",
        "independent_cache": true
    },
    "inbounds": [
       
        {
            "type": "mixed",
            "listen": "::",
            "listen_port": 7890
        },
        {
            "type": "direct",
            "tag": "dns-in",
            "listen": "::",
            "listen_port": 6666
        },
        {
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "::",
            "listen_port": 7896,
            "tcp_fast_open": true,
            "sniff": true,
            "sniff_override_destination": false,
            "sniff_timeout": "100ms"
        }
    ],
    "outbound_providers": [
        {
            "type": "remote",
            "path": "/etc/sing-box/providers/airport1.yaml",
            "tag": "机场",
            "healthcheck_url": "http://www.gstatic.com/generate_204",
            "healthcheck_interval": "10m0s",
            "download_url": "'"$suburl"'",
            "download_ua": "clash.meta",
            "download_interval": "24h0m0s",
            "download_detour": "direct"
        }
    ],
    "outbounds": [
        {
            "tag": "♾️Global",
            "type": "selector",
            "outbounds": [
                "机场节点"
            ]
        },
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        },
        {
            "type": "dns",
            "tag": "dns-out"
        },
        {
            "type": "selector",
            "tag": "机场节点",
            "providers": [
                "机场"
            ],

            "interrupt_exist_connections": true
        }
    ],
    "route": {
        "final": "♾️Global",
        "auto_detect_interface": true,
        "default_mark": 1,
        "rules": [
            {
                "protocol": "dns",
                "outbound": "dns-out"
            },
            {
                "inbound": "dns-in",
                "outbound": "dns-out"
            },
            {
                "clash_mode": "direct",
                "outbound": "direct"
            },
            {
                "clash_mode": "global",
                "outbound": "♾️Global"
            },
            {
                "network": "udp",
                "port": 443,
                "outbound": "block"
            },
            {
                "ip_is_private": true,
                "outbound": "direct"
            },
            {
                "domain_suffix": [
                    ".cn"
                ],
                "outbound": "direct"
            },
            {
                "domain_suffix": [
                    "office365.com"
                ],
                "outbound": "direct"
            },
            {
                "domain_regex": "^-cn-ssl.ls.apple.com",
                "domain_suffix": [
                    "push.apple.com",
                    "iphone-ld.apple.com",
                    "lcdn-locator.apple.com",
                    "lcdn-registration.apple.com"
                ],
                "outbound": "direct"
            },
            {
                "domain_suffix": [
                    "microsoft.com",
                    "ourbits.club",
                    "browserleaks.com"
                ],
                "outbound": "♾️Global"
            },
            {
                "rule_set": "geosite-cn",
                "outbound": "direct"
            },
            {
                "rule_set": "geosite-category-games-cn",
                "outbound": "direct"
            },
            {
                "rule_set": [
                    "geosite-category-scholar-!cn",
                    "geosite-category-scholar-cn"
                ],
                "outbound": "direct"
            },
            {
                "rule_set": "geoip-cn",
                "outbound": "direct"
            },
            {
                "domain_suffix": [
                    "googleapis.com",
                    "googleapis.cn",
                    "gstatic.com"
                ],
                "outbound": "♾️Global"
            },
            {
                "rule_set": "geosite-geolocation-!cn",
                "outbound": "♾️Global"
            },
            {
                "rule_set": [
                    "geoip-telegram",
                    "geosite-telegram"
                ],
                "outbound": "♾️Global"
            },
            {
                "rule_set": [
                    "geoip-google",
                    "geosite-google"
                ],
                "outbound": "♾️Global"
            },
            {
                "rule_set": "geoip-cn",
                "invert": true,
                "outbound": "♾️Global"
            }
        ],
        "rule_set": [
            {
                "tag": "geoip-google",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/google.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geoip-telegram",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/telegram.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geoip-twitter",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/twitter.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geoip-facebook",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/facebook.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geoip-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/netflix.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geoip-hk",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/hk.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geoip-mo",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/mo.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-openai",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-youtube",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-google",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/google.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-github",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/github.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-telegram",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/telegram.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-twitter",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/twitter.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-facebook",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/facebook.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-instagram",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/instagram.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-amazon",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/amazon.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-apple",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/apple.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-apple-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/apple@cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-microsoft",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/microsoft.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-microsoft-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/microsoft@cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-category-games",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-games.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-category-games-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-games@cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-bilibili",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/bilibili.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-tiktok",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/tiktok.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-hbo",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/hbo.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-disney",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/disney.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-primevideo",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/primevideo.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-geolocation-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-category-ads-all",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-category-scholar-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-scholar-!cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            },
            {
                "tag": "geosite-category-scholar-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-scholar-cn.srs",
                "download_detour": "direct",
                "update_interval": "7d"
            }
        ]
    }
}
 }' > /etc/sing-box/config.json
 }
################################安装tproxy################################
install_tproxy() {
    sleep 1
echo "创建系统转发"
# 判断是否已存在 net.ipv4.ip_forward=1
if ! grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
fi

# 判断是否已存在 net.ipv6.conf.all.forwarding = 1
if ! grep -q '^net.ipv6.conf.all.forwarding = 1$' /etc/sysctl.conf; then
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
fi
echo "系统转发创建完成"
    sleep 1
    echo "开始创建nftables tproxy转发"
    apt install nftables -y
# 写入tproxy rule    
# 判断文件是否存在
if [ ! -f "/etc/systemd/system/sing-box-router.service" ]; then
    cat <<EOF > "/etc/systemd/system/sing-box-router.service"
[Unit]
Description=sing-box TProxy Rules
After=network.target
Wants=network.target

[Service]
User=root
Type=oneshot
RemainAfterExit=yes
# there must be spaces before and after semicolons
ExecStart=/sbin/ip rule add fwmark 1 table 100 ; /sbin/ip route add local default dev lo table 100 ; /sbin/ip -6 rule add fwmark 1 table 101 ; /sbin/ip -6 route add local ::/0 dev lo table 101
ExecStop=/sbin/ip rule del fwmark 1 table 100 ; /sbin/ip route del local default dev lo table 100 ; /sbin/ip -6 rule del fwmark 1 table 101 ; /sbin/ip -6 route del local ::/0 dev lo table 101

[Install]
WantedBy=multi-user.target
EOF
    echo "sing-box-router 服务创建完成"
else
    echo "警告：sing-box-router 服务文件已存在，无需创建"
fi
################################写入nftables################################
check_interfaces
echo "" > "/etc/nftables.conf"
cat <<EOF > "/etc/nftables.conf"
#!/usr/sbin/nft -f
flush ruleset
table inet singbox {
  set local_ipv4 {
    type ipv4_addr
    flags interval
    elements = {
      10.0.0.0/8,
      127.0.0.0/8,
      169.254.0.0/16,
      172.16.0.0/12,
      192.168.0.0/16,
      240.0.0.0/4
    }
  }

  set local_ipv6 {
    type ipv6_addr
    flags interval
    elements = {
      ::ffff:0.0.0.0/96,
      64:ff9b::/96,
      100::/64,
      2001::/32,
      2001:10::/28,
      2001:20::/28,
      2001:db8::/32,
      2002::/16,
      fc00::/7,
      fe80::/10
    }
  }

  chain singbox-tproxy {
    fib daddr type { unspec, local, anycast, multicast } return
    ip daddr @local_ipv4 return
    ip6 daddr @local_ipv6 return
    udp dport { 123 } return
    meta l4proto { tcp, udp } meta mark set 1 tproxy to :7896 accept
  }

  chain singbox-mark {
    fib daddr type { unspec, local, anycast, multicast } return
    ip daddr @local_ipv4 return
    ip6 daddr @local_ipv6 return
    udp dport { 123 } return
    meta mark set 1
  }

  chain mangle-output {
    type route hook output priority mangle; policy accept;
    meta l4proto { tcp, udp } skgid != 1 ct direction original goto singbox-mark
  }

  chain mangle-prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname { wg0, lo, $selected_interface } meta l4proto { tcp, udp } ct direction original goto singbox-tproxy
  }
}
EOF
    echo "nftables规则写入完成"
    echo "清空 nftalbes 规则"
    nft flush ruleset
    sleep 1
    echo "新规则生效"
    sleep 1
    nft -f /etc/nftables.conf
    echo "启用并立即启动nftables服务"
    systemctl enable --now nftables
    install_over
}
################################sing-box安装结束################################
install_over() {
    echo "开始启动sing-box"
    systemctl enable --now sing-box-router
    systemctl enable --now sing-box
}
################################设置时区################################
set_timezone() {
    echo -e "\n设置时区为Asia/Shanghai"
    timedatectl set-timezone Asia/Shanghai || { echo -e "\e[31m时区设置失败！退出脚本\e[0m"; exit 1; }
    echo -e "\e[32m时区设置成功\e[0m"
}

################################安装 mosdns################################
install_mosdns() {
    local mosdns_host="https://github.com/IrineSistiana/mosdns/releases/download/v5.3.1/mosdns-linux-amd64.zip"
    set_timezone  || exit 1
    mosdns_customize_settings || exit 1
    download_mosdns || exit 1
    extract_and_install_mosdns || exit 1
    configure_mosdns || exit 1
    enable_autostart || exit 1
    install_complete
}
################################用户自定义设置################################
mosdns_customize_settings() {
    echo -e "\n自定义设置（以下设置可直接回车使用默认值）"
    read -p "输入sing-box入站地址端口（默认10.10.10.147:6666）：" uiport
    uiport="${uiport:-10.10.10.147:6666}"
    echo -e "已设置Singbox入站地址：\e[36m$uiport\e[0m"
    modify_dns_stub_listener
}
################################下载 mosdns################################
download_mosdns() {
    echo "开始下载 mosdns"
    wget "${mosdns_host}" || { echo -e "\e[31m下载失败！退出脚本\e[0m"; exit 1; }
}
################################解压并安装 mosdns################################
extract_and_install_mosdns() {
    echo "开始解压"
    unzip ./mosdns-linux-amd64.zip 
    echo "复制 mosdns 到 /usr/bin"
    sleep 1
    cp -rv ./mosdns /usr/bin
    chmod 0777 /usr/bin/mosdns 
}
#################################配置 mosdns################################
configure_mosdns() {
    echo "配置mosdns规则"
    sleep 1
    cd /etc
    wget -O mosdns.zip https://file.herozmy.com/File/sing-box/mosdns.zip
    unzip mosdns.zip
    echo "配置mosdns"
    sed -i "s/- addr: 10.10.10.147:6666/- addr: ${uiport}/g" /etc/mosdns/config.yaml
}
################################开机自启动 服务################################
enable_autostart() {
    echo "设置mosdns开机自启动"
    mosdns service install -d /etc/mosdns -c /etc/mosdns/config.yaml
    echo "mosdns开机启动完成"
    sleep 1
}
################################mosdns安装结束################################
install_complete() {
    systemctl restart mosdns
    sleep 2
echo "=================================================================="
echo -e "\t\t\Mosdns fake安装完成"
echo -e "\t\t\tPowered by www.herozmy.com 2024"
echo -e "\n"
echo -e "温馨提示:\nMosdns网关自行配置为sing-box，dns随意"
echo -e "本脚本仅适用于学习与研究等个人用途，请勿用于任何违反国家法律的活动！"
echo "=================================================================="
}
################################sing-box安装结束################################
install_sing_box_over() {
echo "=================================================================="
echo -e "\t\t\tSing-Box 安装完毕"
echo -e "\t\t\tPowered by www.herozmy.com 2024"
echo -e "\n"
echo -e "singbox运行目录为/etc/sing-box"
echo -e "singbox WebUI地址:http://ip:9090"
echo -e "温馨提示:\n本脚本仅在 LXC ubuntu22.04 环境下测试，其他环境未经验证，仅供个人使用"
echo -e "本脚本仅适用于学习与研究等个人用途，请勿用于任何违反国家法律的活动！"
echo "=================================================================="
}
################################P sing-box安装结束################################
install_p_sing_box_over() {
echo "=================================================================="
echo -e "\t\t\tP核 Sing-Box 安装完毕"
echo -e "\t\t\tPowered by www.herozmy.com 2024"
echo -e "\n"
echo -e "singbox运行目录为/etc/sing-box"
echo -e "singbox WebUI地址:http://ip:9090"
echo -e "温馨提示:\n本脚本仅在 LXC ubuntu22.04 环境下测试，其他环境未经验证，仅供个人使用"
echo -e "本脚本仅适用于学习与研究等个人用途，请勿用于任何违反国家法律的活动！"
echo "=================================================================="
}
main