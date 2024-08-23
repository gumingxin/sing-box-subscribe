function FindProxyForURL(url, host) {
    var directDomains = [
        "*.cn",
        "*.com.cn",
        "*.gov.cn",
        "*.edu.cn",
        "cn",
        "*.asia",
        "baidu.com",
        "jd.com",
        "toutiao.com",
        "toutiaoapi.com",
        "toutiaocdn.com",
        "toutiaocloud.com",
        "toutiaocloud.net",
        "toutiaohao.com",
        "toutiaohao.net",
        "toutiaoimg.com",
        "toutiaoimg.net",
        "toutiaopage.com",
        "toutiaostatic.com",
        "toutiaovod.com",
        "taobao.com"
    ];

    for (var i = 0; i < directDomains.length; i++) {
        if (dnsDomainIs(host, directDomains[i]) || shExpMatch(host, directDomains[i])) {
            return "DIRECT";
        }
		if (isInNet(host, "192.168.1.0", "255.255.255.255")) {
        return "DIRECT"; 
    }
    }

    return "PROXY 114.226.9.29:8123";
}
