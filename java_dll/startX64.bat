
java -jar ./jnaerator.jar ./build/windows/x64/release/*.dll ./src/hello.h -mode StandaloneJar  -runtime JNA  
copy /y .\build\windows\x64\release\hello.dll  .\
 
echo 脚本执行完成
@pause