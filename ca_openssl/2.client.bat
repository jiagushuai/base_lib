
echo 1.用户生成密钥对[pem文件]
openssl genrsa -out priKey.pem 2048

echo 1.1.生成p10请求
openssl req -new -key priKey.pem -out pkcs10.pem -subj /CN=linggo/O=lingg_O/OU=lingg_OU/ST=GuangDong/L=GuangZhou/C=CN  -config openssl.cnf

echo 2.使用CA证书及CA密钥 对请求证书进行签发 生成x509证书[pem文件]
openssl x509 -req -in pkcs10.pem -out x509.pem -CA ca_x509.pem -CAkey ca_priKey.pem -CAcreateserial

echo 3.根据密钥对和x509证书生成密码为888888的证书文件p12
openssl pkcs12 -export -clcerts -in x509.pem -inkey priKey.pem -out p12.p12  -passout  pass:888888
@pause
