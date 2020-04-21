#pragma once
class rsaLib
{
public:
	rsaLib();
	~rsaLib();

	// 生成密钥对及证书请求
	int genRsaCsr(const char * DN,char * csr, int *csrLen);
	

};

