# TcpPassword

一个内网穿透的密码保护工具, 皆在保护用户将一些高度敏感服务(比如RDP等)穿透到公网中 <br/>

界面来自: Sakura Frp 访问认证

## 使用教程

首先从 [Release](https://github.com/daijunhaoMinecraft/Tcp_Gateway/releases)  处下载你系统对应版本的对应文件 <br/>

然后创建一个文件夹, 名字建议不带中文 <br/>

之后将从 [Release](https://github.com/daijunhaoMinecraft/Tcp_Gateway/releases) 处下载的文件放入此文件夹中<br/>

然后下载对应的 [config.example.json](https://github.com/daijunhaoMinecraft/Tcp_Gateway/blob/main/config.example.json) 配置文件, 然后放到你创建的文件夹目录下, 并将该配置文件修改成文件名称: config.json 随后将这个文件放到你创建的文件夹下, 就像下面这张图: <br/>

![](https://raw.githubusercontent.com/daijunhaoMinecraft/Image/main/mainimage-20260503214656270.png)

随后修改配置文件 config.json, 以下是对该配置内容的注解

``````json
{
    "authHttpPort": 3390, // 认证端口
    "tcpPort": 3391, // 服务转发到的TCP端口
    "targetIp": "127.0.0.1", // 连接目标IP(建议内网)
    "targetPort": 3389, // 连接目标端口
    "authPassword": "YOUR_PASSWORD_HERE", // 访问认证密码
    "whitelistTimeout": 3600, // 认证有效期, 即为每次认证成功后的开放时间, 超过该时间需重新登录(单位秒)
    "persistWhitelist": false, // 持久化白名单保存(存放于当前目录/whitelist.json)
    "pushNotification": { // 推送服务(目前只有Server酱3的推送服务: sc3.ft07.com )
        "enabled": true, // 启用开关
        "service": "serverchan", // 推送服务名称(目前只有Server酱3, 也就是 sc3.ft07.com)
        "sendKey": "your_uid_your_sendkey", // SendKey(发送KEY)
        "maxAttempts": 10, // 单IP认证最大密码尝试次数(超过该次数将会发送警报并且封禁)
        "timeWindow": 60, //
        "banDuration": 1800, // 封禁时长 (单位秒)
        "reportCount": 10 // 报告前<reportCount>个尝试密码数量,若数值超过maxAttempts将会显示前<maxAttempts>个尝试密码
    }
}
``````

修改完成后保存(不要有注解, 否则会报错), 之后打开程序: <br/>

![image-20260503214924975](https://raw.githubusercontent.com/daijunhaoMinecraft/Image/main/mainimage-20260503214924975.png)

当出现这种提示的时候代表成功了

## 内网穿透我要如何获取真实IP

首先是 "TCP 连接端口": **需在内网穿透的设置中增加: proxy_protocol_version = v2 用于启用对 HAProxy V2 的支持**

然后是 "HTTP 认证端口": 请参考这篇文章: [获取访问者的真实 IP | SakuraFrp 帮助文档](https://doc.natfrp.com/bestpractice/realip.html)

## 使用截图

![image-20260503182004991](https://raw.githubusercontent.com/daijunhaoMinecraft/Image/main/mainimage-20260503182004991.png)

![image-20260503182045438](https://raw.githubusercontent.com/daijunhaoMinecraft/Image/main/mainimage-20260503182045438.png)

## 鸣谢
感谢 [Linux.do] (https://linux.do) 的宣传
