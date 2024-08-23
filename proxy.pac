function FindProxyForURL(url, host) {
    var directDomains = [
        "*.cn",
        "*.com.cn",
        "*.gov.cn",
        "*.edu.cn",
        "cn",
        "sina.com",
        "baidu.com",
        "jd.com",
        "taobao.com"
    ];

    for (var i = 0; i < directDomains.length; i++) {
        if (dnsDomainIs(host, directDomains[i]) || shExpMatch(host, directDomains[i])) {
            return "DIRECT";
        }
    }

    return "PROXY 114.226.9.29:8123";
}