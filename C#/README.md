# C#
C#调用C++的动态链接库示例

```
├─bin                   项目的生成目录，动态链接库要在这里才能读取
├─C++                   动态链接库的源码
    ├─src       		源码 包括头文件等
    ├─vs2015          	vs2015的项目文件 打开vs2015.sln即可
    └─xmake.lua    		xmake.lua配置文件
├─demo.csproj           C#工程项目文件 用vs2015打开这个即可
└─README.md             说明文件
```

+ 直接打开vs2015/vs2015.sln文件即可编译工程



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
