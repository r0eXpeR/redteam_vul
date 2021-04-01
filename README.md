# 红队中易被攻击的一些重点系统漏洞整理

以下时间为更新时间，不代表漏洞发现时间.带 ⚒️图标的为工具URL.

配合EHole(棱洞)-红队重点攻击系统指纹探测工具使用效果更佳：https://github.com/EdgeSecurityTeam/EHole

此项目同步至：https://forum.ywhack.com/bountytips.php?Vulnerability

## 一、OA系统

> 泛微(Weaver-Ecology-OA)

* [2021.01.07] - [泛微OA E-cology RCE(CNVD-2019-32204)](https://xz.aliyun.com/t/6560) - 影响版本7.0/8.0/8.1/9.0
* [2021.01.07] - [泛微OA WorkflowCenterTreeData接口注入(限oracle数据库)](https://zhuanlan.zhihu.com/p/86082614)
* [2021.01.07] - [泛微ecology OA数据库配置信息泄露](https://www.cnblogs.com/whoami101/p/13361254.html)
* [2021.01.07] - [泛微OA云桥任意文件读取](https://www.cnblogs.com/yuzly/p/13677238.html) - 影响2018-2019 多个版本
* [2021.01.07] - [泛微 e-cology OA 前台SQL注入漏洞](https://www.cnblogs.com/ffx1/p/12653555.html)
* [2021.01.07] - [泛微OA系统 com.eweaver.base.security.servlet.LoginAction 参数keywordid SQL注入漏洞](https://www.seebug.org/vuldb/ssvid-91089)
* [2021.01.07] - [泛微 OA sysinterface/codeEdit.jsp 页面任意文件上传](https://www.cnblogs.com/whoami101/p/13361254.html)
* [2021.01.07] - [泛微ecology OA数据库配置信息泄露](https://www.seebug.org/vuldb/ssvid-90524)

> 致远(Seeyon)

* [2021.01.07] - [致远 OA A8 htmlofficeservlet getshell 漏洞](https://www.cnblogs.com/nul1/p/12803555.html)
* [2021.01.07] - [致远OA Session泄漏漏洞](https://www.zhihuifly.com/t/topic/3345)
* [2021.01.07] - [致远OA A6 search_result.jsp sql注入漏洞](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)
* [2021.01.07] - [致远OA A6 setextno.jsp sql注入漏洞](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)
* [2021.01.07] - [致远OA A6 重置数据库账号密码漏洞](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)
* [2021.01.07] - [致远OA A8 未授权访问](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)
* [2021.01.07] - [致远OA A8-v5 任意用户密码修改](http://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2015-0104942)
* [2021.01.07] - [致远OA A8-m 后台万能密码](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)
* [2021.01.07] - [致远OA 帆软报表组件 前台XXE漏洞](https://landgrey.me/blog/8/)
* [2021.01.07] - [致远OA帆软报表组件反射型XSS&SSRF漏洞](https://landgrey.me/blog/7/) - Thanks:@LandGrey

> 蓝凌OA

* [2021.01.07] - 暂无(希望大佬能提供) 

> 通达OA(TongDa OA)

* [2021.01.07] - [通达OA任意文件删除&文件上传RCE分析(2020年hw 8月0day)](https://xz.aliyun.com/t/8430)
* [2021.01.07] - [通达OA任意文件上传/文件包含GetShell](https://xz.aliyun.com/t/7437)
* [2021.01.07] - [通达OA <11.5版本 任意用户登录](http://www.adminxe.com/1095.html)
* [2021.01.07] - [通达OA 11.2后台getshell](https://www.cnblogs.com/yuzly/p/13606314.html)
* [2021.01.07] - [通达OA 11.7 后台sql注入getshell漏洞](https://www.cnblogs.com/yuzly/p/13690737.html)
* [2021.03.06] - [通达OA 11.7 未授权RCE](https://mp.weixin.qq.com/s/LJRI04VViL4hbt6dbmGHAw)
* [2021.03.09] - [通达OA 11.8 后台低权限Getshell](https://paper.seebug.org/1499/)
* [2021.03.07] - ⚒️[TDOA_RCE 通达OA综合利用工具](https://github.com/xinyu2428/TDOA_RCE)

> 金蝶OA(Kingdee OA)

* [2021.01.07] - [金蝶协同办公系统 GETSHELL漏洞](https://www.seebug.org/vuldb/ssvid-93826)


## 二、E-mail

> Exchange

* [2021.01.07] - [CVE-2020-17083 Microsoft Exchange Server 远程执行代码漏洞](https://srcincite.io/advisories/src-2020-0025/)
* [2021.01.07] - [Microsoft Exchange远程代码执行漏洞（CVE-2020-16875）](https://github.com/rapid7/metasploit-framework/pull/14126)
* [2021.01.07] - [CVE-2020-0688_微软EXCHANGE服务的远程代码执行漏洞](https://xz.aliyun.com/t/7321)
* [2021.01.07] - [Microsoft Exchange任意用户伪造漏洞](https://xz.aliyun.com/t/3670)
* [2021.03.08] - ⚒️[Microsoft Exchange SSRF（CVE-2021-26855）](https://github.com/GreyOrder/CVE-2021-26855)
* [2021.01.07] - [Exchange 历史漏洞合集](https://sploitus.com/?query=Exchange#exploits)
* [2021.03.10] - [Microsoft Exchange Proxylogon漏洞利用链](https://www.praetorian.com/blog/reproducing-proxylogon-exploit/)

> Coremail

* [2021.01.07] - [Coremail 配置信息泄露及接口未授权漏洞](https://www.lsablog.com/networksec/penetration/coremail-info-leakage-and-webservice-unauthorization-reproduce/)
* [2021.01.07] - [Coremail 存储型XSS漏洞](https://www.seebug.org/vuldb/ssvid-94754)
* [2021.01.07] - [Coremail 历史漏洞合集](https://sploitus.com/?query=Coremail#exploits)


## 三、Web中间件

> Apache

* [2021.01.07] - [Apache Solr RCE—【CVE-2019-0192】](https://xz.aliyun.com/t/4422)
* [2021.01.07] - [CVE-2018-1335：Apache Tika 命令注入](https://xz.aliyun.com/t/4452)
* [2021.01.07] - [Apache Axis1（<=1.4版本） RCE](https://xz.aliyun.com/t/5513)
* [2021.01.07] - [Tomcat信息泄漏和远程代码执行漏洞【CVE-2017-12615/CVE-2017-12616】](https://xz.aliyun.com/t/54)
* [2021.01.07] - [Tomcat Ghostcat - AJP协议文件读取/文件包含漏洞](https://xz.aliyun.com/t/7683)
* [2021.01.07] - [Tomcat全版本命令执行漏洞 CVE-2019-0232](https://github.com/pyn3rd/CVE-2019-0232)
* [2021.01.07] - [Tomcat后台部署war木马getshell](https://blog.csdn.net/weixin_43071873/article/details/109532160)
* [2021.01.07] - [CVE-2016-1240 Tomcat本地提权漏洞](https://blog.csdn.net/jlvsjp/article/details/52776377)
* [2021.01.07] - [Tomcat历史漏洞合集](https://sploitus.com/?query=tomcat#exploits)

> Weblogic

* [2021.01.07] - [CVE-2020-14882 Weblogic 未授权绕过RCE](https://github.com/jas502n/CVE-2020-14882)
* [2021.01.07] - [Weblogic 远程命令执行漏洞分析(CVE-2019-2725)](https://xz.aliyun.com/t/5024)
* [2021.01.07] - [CVE-2019-2618任意文件上传漏洞](https://www.cnblogs.com/lijingrong/p/13049569.html)
* [2021.01.07] - [WebLogic XMLDecoder反序列化漏洞（CVE-2017-10271）](https://www.cnblogs.com/xiaozi/p/8205107.html)
* [2021.01.07] - [Weblogic任意文件读取漏洞（CVE-2019-2615)与文件上传漏洞（CVE-2019-2618）](https://xz.aliyun.com/t/5078)
* [2021.01.07] - [Weblogic coherence组件iiop反序列化漏洞 (CVE-2020-14644)](https://xz.aliyun.com/t/8155)
* [2021.03.07] - [WebLogic CVE-2020-14756 T3/IIOP 反序列化RCE](https://github.com/Y4er/CVE-2020-14756)
* [2021.03.07] - [Weblogic Server远程代码执行漏洞(CVE-2021-2109)](https://forum.ywhack.com/viewthread.php?tid=115007)
* [2021.01.07] - [Weblogic历史漏洞合集](https://sploitus.com/?query=weblogic#exploits)
* [2021.03.09] - ⚒️[WeblogicScan Weblogic一键漏洞检测工具](https://github.com/rabbitmask/WeblogicScan)

> JBoss

* [2021.01.07] - [CVE-2017-7504-JBoss JMXInvokerServlet 反序列化](https://www.cnblogs.com/null1433/p/12704908.html)
* [2021.01.07] - [JBoss 5.x/6.x 反序列化漏洞（CVE-2017-12149）](https://www.cnblogs.com/kuaile1314/p/12060366.html)
* [2021.01.07] - [JBoss 4.x JBossMQ JMS 反序列化漏洞（CVE-2017-7504）](https://www.cnblogs.com/iamver/p/11282928.html)
* [2021.01.07] - [JBOSS远程代码执行漏洞](https://www.cnblogs.com/Safe3/archive/2010/01/08/1642371.html)
* [2021.01.07] - [JBoss JMX Console未授权访问Getshell](https://www.cnblogs.com/rnss/p/13377321.html)
* [2021.01.07] - [JBoss历史漏洞合集](https://sploitus.com/?query=JBoss#exploits)
* [2021.03.10] - ⚒️[JbossScan 一个简单探测jboss漏洞的工具](https://github.com/GGyao/jbossScan)


## 四、源代码管理

> GitLab

* [2021.01.07] - [GitLab任意文件读取漏洞 CVE-2020-10977](https://github.com/thewhiteh4t/cve-2020-10977)
* [2021.01.07] - [GitLab 远程代码执行漏洞 -【CVE-2018-14364】](https://xz.aliyun.com/t/2661)
* [2021.01.07] - [GitLab 任意文件读取 (CVE-2016-9086) 和任意用户token泄露漏洞](https://xz.aliyun.com/t/393)
* [2021.01.07] - [GitLab历史漏洞合集](https://sploitus.com/?query=Gitlab#exploits)

> SVN

* [2021.01.07] - [SVN源码泄露漏洞](https://blog.csdn.net/qq_36869808/article/details/88846945)
* [2021.03.09] - ⚒️[svnExploit 支持SVN源代码泄露全版本Dump源码](https://github.com/admintony/svnExploit)


## 五、项目管理系统

> 禅道

* [2021.01.07] - [【组件攻击链】禅道项目管理系统(ZenTaoPMS)高危漏洞分析与利用](https://www.4hou.com/posts/VoOW)
* [2021.01.07] - [CNVD-C-2020-121325 禅道开源版文件上传漏洞](https://blog.csdn.net/qq_36197704/article/details/109385695)
* [2021.01.07] - [禅道9.1.2 免登陆SQL注入漏洞](https://xz.aliyun.com/t/171/)
* [2021.01.07] - [禅道 ≤ 12.4.2 后台管理员权限Getshell](https://www.cnblogs.com/ly584521/p/13962816.html)
* [2021.01.07] - [禅道9.1.2 权限控制逻辑漏洞](https://xz.aliyun.com/t/186)
* [2021.01.07] - [禅道826版本一定条件getshell](https://xz.aliyun.com/t/188)
* [2021.01.07] - [禅道远程代码执行漏洞](https://anquan.baidu.com/article/996)
* [2021.01.07] - [禅道11.6任意文件读取](https://wiki.bylibrary.cn/01-CMS%E6%BC%8F%E6%B4%9E/%E7%A6%85%E9%81%93/%E7%A6%85%E9%81%9311.6%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96/)

> Jira

* [2021.01.07] - [Atlassian Jira漏洞大杂烩](https://caiqiqi.github.io/2019/11/03/Atlassian-Jira%E6%BC%8F%E6%B4%9E%E5%A4%A7%E6%9D%82%E7%83%A9/)
* [2021.01.07] - [Jira服务工作台路径遍历导致的敏感信息泄露漏洞（CVE-2019-14994）](https://cloud.tencent.com/developer/article/1529135)
* [2021.01.07] - [Jira未授权SSRF漏洞(CVE-2019-8451)](https://www.cnblogs.com/backlion/p/11608371.html)
* [2021.01.07] - [Atlassian JIRA服务器模板注入漏洞（CVE-2019-11581）](https://www.cnblogs.com/backlion/p/11608439.html)
* [2021.01.07] - [CVE-2019-8449 JIRA 信息泄漏漏洞](https://xz.aliyun.com/t/7219)
* [2021.01.07] - ⚒️[遇到Jira时可以尝试的一些CVE](https://twitter.com/harshbothra_/status/1346109605756116995)
* [2021.01.07] - [Jira历史漏洞合集](https://sploitus.com/?query=Jira#exploits)


## 六、数据库

* [2021.03.09] - ⚒️[MDAT 多种主流的数据库攻击利用工具](https://github.com/SafeGroceryStore/MDAT)

> Redis

* [2021.01.07] - [Redis未授权访问漏洞利用总结](https://xz.aliyun.com/t/256)
* [2021.01.07] - [Redis 4.x RCE](https://xz.aliyun.com/t/5616)
* [2021.01.07] - [redis利用姿势收集](https://www.webshell.cc/5154.html)
* [2021.01.07] - [Redis历史漏洞合集](https://sploitus.com/?query=redis#exploits)
* [2021.03.08] - ⚒️[通过 Redis 主从写出无损文件](https://github.com/r35tart/RedisWriteFile)

> Mysql

* [2021.01.07] - [Mysql提权(CVE-2016-6663、CVE-2016-6664组合实践)](https://xz.aliyun.com/t/1122)
* [2021.01.07] - [Mysql数据库渗透及漏洞利用总结](https://blog.csdn.net/itfly8/article/details/100890881)
* [2021.01.07] - [Mysql 注入专辑](https://www.cnblogs.com/ichunqiu/p/9604564.html)
* [2021.01.07] - [高版本MySQL之UDF提权](https://xz.aliyun.com/t/2199)
* [2021.03.08] - [Mysql历史漏洞合集](https://sploitus.com/?query=mysql#exploits)

> Mssql

* [2021.01.07] - [Mssql利用姿势整理(整理的比较全)](https://forum.ywhack.com/thread-114737-1-1.html)
* [2021.01.07] - [Mssql数据库命令执行总结](https://xz.aliyun.com/t/7534)
* [2021.01.07] - [利用mssql模拟登录提权](https://xz.aliyun.com/t/8195)
* [2021.01.07] - [高级的MSSQL注入技巧](https://xz.aliyun.com/t/8513)
* [2021.03.08] - [MSSQL使用CLR程序集来执行命令](https://xz.aliyun.com/t/6682)

## 七、开源运维监控

> Jenkins

* [2021.03.10] -  [Jenkins 路径遍历任意文件写入漏洞（CVE-2019-10352）](https://blog.csdn.net/caiqiiqi/article/details/96431428)
* [2021.03.10] -  [Jenkins Git client插件命令执行漏洞(CVE-2019-10392)](https://www.cnblogs.com/paperpen/p/11626231.html)
* [2021.03.10] -  [Jenkins 历史漏洞利用程序](https://sploitus.com/?query=Jenkins#exploits)

> Zabbix

* [2021.03.10] -  [CVE-2020-11800 Zabbix 远程代码执行漏洞](https://xz.aliyun.com/t/8991)
* [2021.03.10] -  [Zabbix 中的CSRF到RCE（CVE-2021-27927）](https://www.horizon3.ai/disclosures/zabbix-csrf-to-rce)
* [2021.03.10] -  [Zabbix 2.2 - 3.0.3 远程代码执行漏洞](https://www.exploit-db.com/exploits/39937)
* [2021.03.10] -  [Zabbix Agent 3.0.1 mysql.size shell命令注入 (CVE-2016-4338)](https://www.seebug.org/vuldb/ssvid-92245)
* [2021.03.10] -  [Zabbix 历史漏洞利用程序](https://sploitus.com/?query=Zabbix#exploits)

> Nagios

* [2021.03.10] -  [Nagios XI 5.6.9 远程代码执行漏洞（CVE-2019-20197）](https://code610.blogspot.com/2019/12/postauth-rce-in-latest-nagiosxi.html)
* [2021.03.10] -  [nagios-xi-5.7.5 多个漏洞（CVE-2021-25296~99）](https://github.com/fs0c-sh/nagios-xi-5.7.5-bugs)
* [2021.03.10] -  [Nagios 代码注入漏洞 (CVE-2021-3273)](https://gist.github.com/leommxj/93edce6f8572cefe79a3d7da4389374e)
* [2021.03.10] -  [Nagios XI 5.5.10: XSS to RCE](https://www.shielder.it/blog/2019/04/nagios-xi-5.5.10-xss-to-/)
* [2021.03.10] -  [Nagios 历史漏洞利用程序](https://sploitus.com/?query=Nagios#exploits)


## 八、堡垒机

> JumpServer

* [2021.03.10] -  [JumpServer远程执行漏洞(2021.01)](https://www.o2oxy.cn/2921.html)

> 齐治堡垒机

* [2021.03.10] -  [齐治堡垒机未授权RCE](https://www.seebug.org/vuldb/ssvid-98383)
* [2021.03.10] -  [齐治堡垒机远程代码执行](https://forum.ywhack.com/viewthread.php?tid=1523)

此项目不定期进行更新......
