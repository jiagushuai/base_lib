# java_dll
C++生成的动态链接库打包为jar包，并提供java测试项目

```
├─.gitignore		设置相应的忽略规则，来忽略这些文件的提交
├─java				java示例程序
├─src				动态链接库dll的源码
├─jnaerator.jar				用它打包dll生成对应的jar包
├─startX64				脚本直接双击运行，逻辑为根据hello.h及hello.dll用jnaerator.jar打包为hello.jar
├─vs2015			vs2015的项目工程文件
└─xmake.lua			xmake.lua配置文件
```

+ 注意：64位与32位不能混用，会报错
+ 直接打开vs2015/vs2015.sln文件即可编译工程
+ 生成的hello.jar里包含hello.dll，但有时候会报错`unable to load library:'hello'`
    + 把hello.dll放在hello.jar同级目录下或者系统目录`C:\Windows\System32`即可
