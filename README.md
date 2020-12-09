# 红队中易被攻击的一些重点系统漏洞整理

## 一、OA系统

#### 泛微(Weaver-Ecology-OA)

🔸 [泛微OA E-cology RCE(CNVD-2019-32204)](https://xz.aliyun.com/t/6560) - 影响版本7.0/8.0/8.1/9.0<br>
🔸 [泛微OA WorkflowCenterTreeData接口注入(限oracle数据库)](https://zhuanlan.zhihu.com/p/86082614)<br>
🔸 [泛微ecology OA数据库配置信息泄露](https://www.cnblogs.com/whoami101/p/13361254.html)<br>
🔸 [泛微OA云桥任意文件读取](https://www.cnblogs.com/yuzly/p/13677238.html) - 影响2018-2019 多个版本<br>
🔸 [泛微 e-cology OA 前台SQL注入漏洞](https://www.cnblogs.com/ffx1/p/12653555.html)<br>
🔸 [泛微OA系统 com.eweaver.base.security.servlet.LoginAction 参数keywordid SQL注入漏洞](https://www.seebug.org/vuldb/ssvid-91089)<br>
🔸 [泛微 OA sysinterface/codeEdit.jsp 页面任意文件上传](https://www.seebug.org/vuldb/ssvid-90524)<br>

#### 致远(Seeyon)

🔸 [致远OA-A8 htmlofficeservlet getshell 漏洞](https://www.cnblogs.com/nul1/p/12803555.html)<br>
🔸 [致远OA Session泄漏漏洞](https://www.zhihuifly.com/t/topic/3345)<br>
🔸 [致远OA A6 search_result.jsp sql注入漏洞](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)<br>
🔸 [致远OA A6 setextno.jsp sql注入漏洞](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)<br>
🔸 [致远OA A6 重置数据库账号密码漏洞](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)<br>
🔸 [致远OA A8 未授权访问](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)<br>
🔸 [致远OA A8-v5 任意用户密码修改](http://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2015-0104942)<br>
🔸 [致远OA A8-m 后台万能密码](https://www.cnblogs.com/AtesetEnginner/p/12106741.html)<br>
🔸 [致远OA 帆软报表组件 前台XXE漏洞](https://landgrey.me/blog/8/)<br>
🔸 [致远OA帆软报表组件反射型XSS&SSRF漏洞](https://landgrey.me/blog/7/)  Thinks:LandGrey<br>

#### 蓝凌OA

暂无(希望大佬能提供)

#### 通达OA

🔸 [通达OA任意文件删除&文件上传RCE分析(2020年hw 8月0day)](https://xz.aliyun.com/t/8430)<br>
🔸 [通达OA任意文件上传/文件包含GetShell](https://xz.aliyun.com/t/7437)<br>
🔸 [通达OA<11.5版本 任意用户登录](http://www.adminxe.com/1095.html)<br>
🔸 [通达OA 11.2后台getshell](https://www.cnblogs.com/yuzly/p/13606314.html)<br>
🔸 [通达OA 11.7 后台sql注入getshell漏洞](https://www.cnblogs.com/yuzly/p/13690737.html)<br>

#### 金蝶OA

🔸 [金蝶协同办公系统 GETSHELL漏洞](https://www.seebug.org/vuldb/ssvid-93826)<br>

## 二、E-mail

#### Exchange

🔸 [CVE-2020-17083 Microsoft Exchange Server 远程执行代码漏洞](https://srcincite.io/advisories/src-2020-0025/)<br>
🔸 [Microsoft Exchange远程代码执行漏洞（CVE-2020-16875）](https://github.com/rapid7/metasploit-framework/pull/14126)<br>
🔸 [CVE-2020-0688_微软EXCHANGE服务的远程代码执行漏洞](https://xz.aliyun.com/t/7321)<br>
🔸 [Microsoft Exchange任意用户伪造漏洞](https://xz.aliyun.com/t/3670)<br>
🔸 [Exchange 历史漏洞合集](https://sploitus.com/?query=Exchange#exploits)<br>

#### coremail

🔸 [coremail 配置信息泄露及接口未授权漏洞](https://www.lsablog.com/networksec/penetration/coremail-info-leakage-and-webservice-unauthorization-reproduce/)<br>
🔸 [Coremail的存储型XSS漏洞](https://www.seebug.org/vuldb/ssvid-94754)<br>
🔸 [Coremail 历史漏洞合集](https://sploitus.com/?query=Coremail#exploits)<br>

## 三、web中间件

#### Apache

🔸 [Apache Solr RCE—【CVE-2019-0192】](https://xz.aliyun.com/t/4422)<br>
🔸 [CVE-2018-1335：Apache Tika 命令注入](https://xz.aliyun.com/t/4452)<br>
🔸 [Apache Axis1（<=1.4版本） RCE](https://xz.aliyun.com/t/5513)<br>
🔸 [Apache Solr 模版注入漏洞(RCE)](https://xz.aliyun.com/t/6700)<br>
🔸 [Apache Shiro权限绕过漏洞(CVE-2020-11989)](https://xz.aliyun.com/t/7964)<br>
🔸 [Shiro remeberMe反序列化漏洞（Shiro-550）](https://www.cnblogs.com/sup3rman/p/13322898.html)<br>
🔸 [Apache历史漏洞合集](https://sploitus.com/?query=Apache#exploits)<br>

#### Tomcat

🔸 [Tomcat信息泄漏和远程代码执行漏洞【CVE-2017-12615/CVE-2017-12616】](https://xz.aliyun.com/t/54)<br>
🔸 [Tomcat Ghostcat - AJP协议文件读取/文件包含漏洞](https://xz.aliyun.com/t/7683)<br>
🔸 [Tomcat全版本命令执行漏洞 CVE-2019-0232](https://github.com/pyn3rd/CVE-2019-0232)<br>
🔸 [Tomcat后台部署war木马getshell](https://blog.csdn.net/weixin_43071873/article/details/109532160)<br>
🔸 [CVE-2016-1240 Tomcat本地提权漏洞](https://blog.csdn.net/jlvsjp/article/details/52776377)<br>
🔸 [Tomcat历史漏洞合集](https://sploitus.com/?query=tomcat#exploits)<br>

#### Weblogic

🔸 [CVE-2020–14882 Weblogic 未经授权绕过RCE](https://www.cnblogs.com/Savior-cc/p/13916900.html)<br>
🔸 [Weblogic 远程命令执行漏洞分析(CVE-2019-2725)](https://xz.aliyun.com/t/5024)<br>
🔸 [CVE-2019-2618任意文件上传漏洞](https://www.cnblogs.com/lijingrong/p/13049569.html)<br>
🔸 [WebLogic XMLDecoder反序列化漏洞（CVE-2017-10271）](https://www.cnblogs.com/xiaozi/p/8205107.html)<br>
🔸 [Weblogic任意文件读取漏洞（CVE-2019-2615)与文件上传漏洞（CVE-2019-2618）](https://xz.aliyun.com/t/5078)<br>
🔸 [Weblogic coherence组件iiop反序列化漏洞 (CVE-2020-14644)](https://xz.aliyun.com/t/8155)<br>
🔸 [Weblogic历史漏洞合集](https://sploitus.com/?query=weblogic#exploits)<br>

#### JBoss

🔸 [CVE-2017-7504-JBoss JMXInvokerServlet 反序列化](https://www.cnblogs.com/null1433/p/12704908.html)<br>
🔸 [JBoss 5.x/6.x 反序列化漏洞（CVE-2017-12149）](https://www.cnblogs.com/kuaile1314/p/12060366.html)<br>
🔸 [JBoss 4.x JBossMQ JMS 反序列化漏洞（CVE-2017-7504）](https://www.cnblogs.com/iamver/p/11282928.html)<br>
🔸 [JBOSS远程代码执行漏洞](https://www.cnblogs.com/Safe3/archive/2010/01/08/1642371.html)<br>
🔸 [JBoss JMX Console未授权访问Getshell](https://www.cnblogs.com/rnss/p/13377321.html)<br>
🔸 [JBoss历史漏洞合集](https://sploitus.com/?query=JBoss#exploits)<br>

## 四、源代码管理

#### GitLab

🔸 [GitLab任意文件读取漏洞CVE-2020-10977](https://github.com/thewhiteh4t/cve-2020-10977)<br>
🔸 [GitLab远程代码执行漏洞分析 -【CVE-2018-14364】](https://xz.aliyun.com/t/2661)<br>
🔸 [GitLab 任意文件读取 (CVE-2016-9086) 和任意用户token泄露漏洞](https://xz.aliyun.com/t/393)<br>
🔸 [GitLab历史漏洞合集](https://sploitus.com/?query=Gitlab#exploits)<br>

#### SVN

🔸 [SVN源码泄露漏洞](https://blog.csdn.net/qq_36869808/article/details/88846945)<br>

## 五、项目管理系统

#### 禅道

🔸 [CNVD-C-2020-121325 禅道开源版文件上传漏洞](https://blog.csdn.net/qq_36197704/article/details/109385695)<br>
🔸 [禅道9.1.2 免登陆SQL注入漏洞](https://xz.aliyun.com/t/171/)<br>
🔸 [禅道 ≤ 12.4.2 后台管理员权限Getshell](https://www.cnblogs.com/ly584521/p/13962816.html)<br>
🔸 [禅道9.1.2 权限控制逻辑漏洞](https://xz.aliyun.com/t/186)<br>
🔸 [禅道826版本一定条件getshell](https://xz.aliyun.com/t/188)<br>
🔸 [禅道远程代码执行漏洞](https://anquan.baidu.com/article/996)<br>
🔸 [禅道11.6任意文件读取](https://wiki.bylibrary.cn/01-CMS%E6%BC%8F%E6%B4%9E/%E7%A6%85%E9%81%93/%E7%A6%85%E9%81%9311.6%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96/)<br>

#### Jira

🔸 [Atlassian Jira漏洞大杂烩](https://caiqiqi.github.io/2019/11/03/Atlassian-Jira%E6%BC%8F%E6%B4%9E%E5%A4%A7%E6%9D%82%E7%83%A9/)<br>
🔸 [Jira服务工作台路径遍历导致的敏感信息泄露漏洞（CVE-2019-14994）](https://cloud.tencent.com/developer/article/1529135)<br>
🔸 [Jira未授权SSRF漏洞(CVE-2019-8451)](https://www.cnblogs.com/backlion/p/11608371.html)<br>
🔸 [Atlassian JIRA服务器模板注入漏洞（CVE-2019-11581）](https://www.cnblogs.com/backlion/p/11608439.html)<br>
🔸 [CVE-2019-8449 JIRA 信息泄漏漏洞](https://xz.aliyun.com/t/7219)<br>
🔸 [Jira历史漏洞合集](https://sploitus.com/?query=Jira#exploits)<br>

## 六、数据库

#### Redis

🔸 [Redis未授权访问漏洞利用总结](https://xz.aliyun.com/t/256)<br>
🔸 [Redis 4.x RCE](https://xz.aliyun.com/t/5616)<br>
🔸 [redis利用姿势收集](https://www.webshell.cc/5154.html)<br>
🔸 [Redis历史漏洞合集](https://sploitus.com/?query=redis#exploits)<br>

#### Mysql

🔸 [Mysql提权(CVE-2016-6663、CVE-2016-6664组合实践)](https://xz.aliyun.com/t/1122)<br>
🔸 [Mysql数据库渗透及漏洞利用总结](https://xz.aliyun.com/t/1)<br>
🔸 [Mysql 注入专辑](https://www.lshack.cn/596/)<br>
🔸 [PhpMyadmin的几种getshell方法](https://www.cnblogs.com/muxueblog/p/13043768.html)<br>
🔸 [高版本MySQL之UDF提权](https://xz.aliyun.com/t/2199)<br>
🔸 [Mysql历史漏洞合集](https://sploitus.com/?query=mysql#exploits)<br>

#### Mssql

🔸 [Mssql利用姿势整理(史上最全)](https://forum.ywhack.com/thread-114737-1-1.html)<br>
🔸 [Mssql数据库命令执行总结](https://xz.aliyun.com/t/7534)<br>
🔸 [利用mssql模拟登录提权](https://xz.aliyun.com/t/8195)<br>
🔸 [高级的MSSQL注入技巧](https://xz.aliyun.com/t/8513)<br>
🔸 [MSSQL使用CLR程序集来执行命令](https://xz.aliyun.com/t/6682)<br>

Author:Unomi   持续更新中.......😄 欢迎**Star**
