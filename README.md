# base_lib
C++总结，包括笔者常使用的各个方法及接口

```
├─.gitignore		设置相应的忽略规则，来忽略这些文件的提
├─sr                    简单示例程序
    ├─base64       	base64编码解码的示例
    ├─log          	打印日志的示例 跨平台包括Windows及Mac
    └─transcode    	gbk与utf8转码的示例	
├─vs2015                vs2015的项目工程文件
├─java_dll              dll打包为jar包供java调用
├─ca_openssl            openssl命令行实现自建ca流程
├─README.md             说明文件
└─xmake.lua             xmake.lua配置文件
```

+ 直接打开vs2015/vs2015.sln文件即可编译工程
+ 实现转码[gbk_utf8],编码[base64],写日志等
+ [乱码在线恢复](http://www.mytju.com/classcode/tools/messyCodeRecover.asp)
+ base_base64中有根据base64编码转换为PDF文件及文件转换为base64字符串的示例

+ 日志输出示例
```
04-18 09:27:25.394 D @test.cpp:24 ==============print.log==============
```
## TODO 
+ openssl相关API实现CA认证流程

## xmake相关
+ 安装等可查阅xmake[中文官网](https://xmake.io/#/zh-cn/)
### 设置Windows平台32位

```
# 配置编译Windows平台 32位
xmake f -p windows -a x86
```

### 根据xmake.lua生成vs项目

```
# 生成vs项目文件
xmake project -k vs2015 -m "debug,release"
# 配置生成vs工程 32位
xmake project -k vs2015 -m "debug,release" -a x86
```

### 编译相关

```
# 编译,加`-v`则显示编译详细信息
xmake -r -v
# 恢复默认配置,配置编译当前平台
xmake f -c
```
