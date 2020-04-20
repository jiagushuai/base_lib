#include "rsaLib.h"
#include <openssl/x509.h>

rsaLib::rsaLib()
{
}


rsaLib::~rsaLib()
{
}

// 生成密钥对及证书请求
int rsaLib::genRsaCsr(const char * DN, char * pfxPwd,
	unsigned char * csr, int * csrLen, unsigned char * priKeyBase64, int * priLen, unsigned  char * pubKeyBase64, int * pubLen)
{
	X509_REQ        *pX509Req = NULL;
	int             iRV = 0;
	X509_NAME       *pX509DN = NULL;
	EVP_PKEY        *pEVPKey = NULL;
	RSA             *pRSA = NULL;
	X509_NAME_ENTRY *pX509Entry = NULL;
	int             bits = 2048;
	unsigned long   E = RSA_F4;

	//if (DN == NULL)
	//{
	//	return SAR_PARAM_NULL;
	//}
	//if (!(pX509DN = X509_NAME_new()))
	//{
	//	return SAR_MEMORYERR;
	//}
	//iRV = genX509NAME(DN, pX509DN);
	//if (iRV != 0)
	//{
	//	ZF_LOGE("genCsr genX509NAME error");
	//	return iRV;
	//}

	pRSA = RSA_generate_key(bits, E, NULL, NULL);
	pEVPKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pEVPKey, pRSA);

	//pX509Req = X509_REQ_new();
	//iRV = genX509REQ(pX509DN, pEVPKey, pX509Req);
	//if (iRV != 0)
	//{
	//	ZF_LOGE("genCsr genX509REQ error");
	//	return iRV;
	//}

	// genCsrPemFile(pX509Req, csr, csrLen);
	// genPriPemFile(pEVPKey, pfxPwd, priKeyBase64, priLen);
	// genRsaPubPemFile(pRSA, pubKeyBase64, pubLen);
	
	X509_REQ_free(pX509Req);
	RSA_free(pRSA);
	return 0;
}

