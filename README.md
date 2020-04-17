# base_lib
C++总结，包括笔者常使用的各个方法及接口

```
├─.gitignore		设置相应的忽略规则，来忽略这些文件的提交
├─base_transcode	gbk与utf8转码的示例
├─base_base64		base64编码解码的示例
├─base_log			打印日志的示例 跨平台包括Windows及Mac
├─base_openssl		openssl实现CA认证的示例
├─base_pkcs11		pkcs11接口函数的示例
├─base_skf			国密SKF接口函数的示例
├─base_csp			csp调用CryptoAPI系列函数的示例
├─src				简单示例程序
├─vs2015			vs2015的项目工程文件
├─README.md			说明文件
└─xmake.lua			xmake.lua配置文件
```

+ 实现转码[gbk_utf8],编码[base64],写日志等
+ [乱码在线恢复](http://www.mytju.com/classcode/tools/messyCodeRecover.asp)
+ base_base64中有根据base64编码转换为PDF文件及文件转换为base64字符串的示例

+ 
## TODO 
+ openssl相关API实现CA认证流程
+ pkcs11相关API使用
+ SKF相关API使用
+ csp相关API使用