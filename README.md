# 2022 HW漏洞

## 网御安全网关存在弱口令漏洞
### 漏洞描述
CNVD-2022-43128
### 漏洞详情
网御安全网关存在弱口令漏洞，攻击者可利用该漏洞获取敏感信息。
## 网御防火墙系统存在信息泄露漏洞
### 漏洞描述
CNVD-2022-48610
### 漏洞详情
网御防火墙系统存在信息泄露漏洞，攻击者可利用该漏洞获取敏感信息。
## 明御Web应用防火墙存在任意登录漏洞
### 漏洞描述
明御Web应用防火墙存在任意登录漏洞
### 漏洞详情
影响版本：X86架构<=4.6.33、信创兆芯=4.5、鲲鹏=4.6.18
代码/waf/php_admin/app/mvc/controllers/controller/report.php中以硬编码形式设置了console用户登录，通过硬编码可以直接登录。
## 明御Web应用防火墙存在远程命令执行漏洞
### 漏洞描述
明御Web应用防火墙存在远程命令执行漏洞
### 漏洞详情
通过任意登录漏洞进入后台，构造恶意的保护站点配置，覆盖/waf/config/misc/webapp.yaml文件，当/waf/system_service/one_way_detect/one_way_detect.php调用webapp.yaml时，其中的ip参数可进行命令注入。因此构造恶意的保护站点配置加密数据包，通过管理员用户登录后台，上传恶意数据包，实现远程命令执行。
## SANGFORVPN存在远程缓冲区溢出漏洞
### 漏洞描述
SANGFOR VPN存在远程缓冲区溢出漏洞
### 漏洞详情
SANGFOR VPN存在远程缓冲区溢出漏洞
## NF防火墙存在远程命令执行漏洞
### 漏洞描述
NSFOCUS NF防火墙存在远程命令执行漏洞
### 漏洞详情
受影响版本：版本<6.0.3.198
## 天擎存在安全漏洞
### 漏洞描述
QAX天擎存在安全漏洞
### 漏洞详情
受影响版本：版本<6.7.0.4910
## LEAGSOFT软件定义边界系统命令执行漏洞
### 漏洞描述
SDP软件定义边界系统命令执行漏洞
### 漏洞详情
LEAGSOFT定义边界系统命令执行漏洞，对于自动提交的用户可控参数没有进行安全检查，可以通过构造特殊参数的数据包，后台在执行过程中直接执行了提交数据包中的命令参数，导致命令执行漏洞。
## LEAGSOFT网络准入控制系统反序列化漏洞
### 漏洞描述
网络准入控制系统反序列化漏洞
### 漏洞详情
网络准入控制系统反序列化漏洞
## 泛微OA存在SQL注入漏洞
### 漏洞描述
CNVD-2022-43843
泛微OA是一款移动办公平台。
泛微OA存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。
### 漏洞详情
受影响版本：泛微OA V8
请升级安全版本，补丁链接：[https://www.weaver.com.cn/cs/securityDownload.html](https://www.weaver.com.cn/cs/securityDownload.html)
## 泛微OA存在命令执行漏洞
### 漏洞描述
CNVD-2022-06870
上海泛微网络科技股份有限公司专注于协同管理OA软件领域，并致力于以协同OA为核心帮助企业构建全新的移动办公平台。
泛微OA存在命令执行漏洞，攻击者可利用该漏洞获取服务器控制权。
### 漏洞详情
受影响版本：泛微OA <8.9
请升级安全版本，补丁链接：[https://www.weaver.com.cn/cs/securityDownload.html](https://www.weaver.com.cn/cs/securityDownload.html)
## 泛微E-cology 8.0/9.0任意文件上传漏洞
### 漏洞描述
泛微E-cology存在任意文件上传漏洞
### 漏洞详情
受影响版本：E-cology 8.0/9.0 10.47以下和其他版本
请升级安全版本，补丁链接：[https://www.weaver.com.cn/cs/securityDownload.html](https://www.weaver.com.cn/cs/securityDownload.html)
## 泛微云桥e-Bridge存在SQL注入漏洞
### 漏洞描述
CNVD-2022-44187
泛微云桥（e-Bridge）是一款用于桥接互联网开放资源与企业信息化系统的系统集成中间件。
泛微云桥存在SQL注入漏洞，攻击者可利用漏洞获取数据库敏感信息。
### 漏洞详情
受影响版本：泛微云桥 v4.0
请升级安全版本，补丁链接：[https://www.weaver.com.cn/cs/securityDownload.html](https://www.weaver.com.cn/cs/securityDownload.html)
## 泛微e-office存在任意文件读取漏洞
### 漏洞描述
CNVD-2022-43245
泛微e-office是一款标准协同移动办公平台。
上海泛微网络科技股份有限公司e-office存在任意文件读取漏洞，攻击者可利用漏洞获取敏感信息。
### 漏洞详情
受影响版本：e-office 9.5 20220113
请升级安全版本，补丁链接：[https://www.weaver.com.cn/cs/securityDownload.html](https://www.weaver.com.cn/cs/securityDownload.html)
## 泛微e-office存在SQL注入漏洞
### 漏洞描述
CNVD-2022-43246
泛微e-office是一款标准协同移动办公平台。
上海泛微网络科技股份有限公司e-office存在SQL注入漏洞，攻击者可利用漏洞获取数据库敏感信息。
### 漏洞详情
受影响版本：e-office v9.0 141103
请升级安全版本，补丁链接：[https://www.weaver.com.cn/cs/securityDownload.html](https://www.weaver.com.cn/cs/securityDownload.html)
## 泛微e-office存在文件包含漏洞
### 漏洞描述
CNVD-2022-43247
泛微e-office是一款标准协同移动办公平台。
上海泛微网络科技股份有限公司e-office存在文件包含漏洞，攻击者可利用漏洞包含文件，导致代码执行。
### 漏洞详情
受影响版本：e-office 9.5 20220113
请升级安全版本，补丁链接：[https://www.weaver.com.cn/cs/securityDownload.html](https://www.weaver.com.cn/cs/securityDownload.html)
## 禅道存在SQL注入漏洞
### 漏洞描述
禅道存在SQL注入漏洞。攻击者可利用漏洞获取数据库敏感信息。
### 漏洞详情
影响版本：禅道企业版 6.5、禅道旗舰版 3.0、禅道开源版 16.5、禅道开源版 16.5.beta1
厂商已提供漏洞修补方案，请关注厂商主页及时更新：[https://www.zentao.net/](https://www.zentao.net/)
## 通达OA存在代码执行漏洞
### 漏洞描述
通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。
通达OA存在代码执行漏洞。攻击者可利用该漏洞获取服务器权限。
### 漏洞详情
受影响版本：通达OA 11.8
请关注厂商主页及时更新：[https://www.tongda2000.com/](https://www.tongda2000.com/)
## 用友U8-OA企业版存在SQL注入漏洞
### 漏洞描述
CNVD-2022-31182
用友U8-OA企业版存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。
### 漏洞详情
受影响版本：用友U8-OA企业版 2.83
请升级安全版本，补丁链接：[https://www.yonyou.com/](https://www.yonyou.com/)
## 致远A8+文件上传漏洞
### 漏洞描述
致远A8+集团版本存在文件上传漏洞
### 漏洞详情
受影响版本：A8+集团版V8.0SP2LTS和其他版本
请升级安全版本，补丁链接：[https://support.seeyon.com/downcenter_bdxz.html](https://support.seeyon.com/downcenter_bdxz.html)
## Laravel存在命令执行漏洞
### 漏洞描述
CNVD-2022-44351
CVE-2022-31279
Laravel存在命令执行漏洞，攻击者可利用漏洞进行远程代码执行（RCE）。
### 漏洞详情
受影响版本：Laravel Laravel 9.1.8
目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：[https://laravel.com/](https://laravel.com/)
