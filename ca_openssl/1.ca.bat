
echo 1.CA生成密钥对[pem文件]
openssl genrsa -out ca_priKey.pem 2048

echo 2.生成p10请求
openssl req -new -key ca_priKey.pem -out ca_pkcs10.pem -subj /CN=gushuai.fun/O=gushuai/OU=linggo/ST=GuangDong/L=GuangZhou/C=CN  -config openssl.cnf

echo 3.CA自签发x509[pem文件]
openssl x509 -req -in ca_pkcs10.pem -out ca_x509.pem -signkey ca_priKey.pem

echo 4.根据密钥对和x509证书生成密码为888888的证书文件p12
openssl pkcs12 -export -clcerts -in ca_x509.pem -inkey ca_priKey.pem -out ca_p12.p12  -passout  pass:888888

@pause
