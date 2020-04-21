#include "rsaLib.h"
#include "opensslBase.h"

rsaLib::rsaLib()
{
}


rsaLib::~rsaLib()
{
}
// 生成密钥对及证书请求
int rsaLib::genRsaCsr(const char * DN, char * csr,int *csrLen)
{
	X509_REQ        *pX509Req = NULL;
	int             iRV = 0;
	X509_NAME       *pX509DN = NULL;
	EVP_PKEY        *pEVPKey = NULL;
	RSA             *pRSA = NULL;
	X509_NAME_ENTRY *pX509Entry = NULL;
	int             bits = 2048;
	unsigned long   E = RSA_F4;

	if (DN == NULL)
	{
		return -1;
	}
	if (csr == NULL || csrLen ==NULL)
	{
		return -1;
	}
	if (!(pX509DN = X509_NAME_new()))
	{
		return -1;
	}

	/*用DN生成X509_NAME结构*/	
	iRV = genX509NAME(DN, pX509DN);
	if (iRV != 0)
	{
		ZF_LOGE("genCsr genX509NAME error");
		return iRV;
	}
	pRSA = RSA_generate_key(bits, E, NULL, NULL);
	pEVPKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pEVPKey, pRSA);
	/*用公钥及刚刚生成的X509_NAME生成证书请求*/
	pX509Req = X509_REQ_new();
	iRV = genX509REQ(pX509DN, pEVPKey, pX509Req);
	if (iRV != 0)
	{
		ZF_LOGE("genCsr genX509REQ error");
		return iRV;
	}
	
	/* DER编码 pri*/
	BUF_MEM         *pBMem = NULL;
	BIO             *pBIO = NULL;
	int             nLen,baseLen= 0;
	unsigned char   *pDer = NULL;
	unsigned char   *p = NULL;

	/*字符串 DER编码 pkcs10*/
	nLen = i2d_X509_REQ(pX509Req, NULL);
	pDer = (unsigned char *)malloc(nLen);
	p = pDer;
	nLen = i2d_X509_REQ(pX509Req, &p);
	baseLen = getEncodeLen(nLen, pDer);//编码后的字符串长度
	memcpy(csr, base64_encode(nLen,pDer), baseLen);
	*csrLen = baseLen;
	free(pDer);
	printf("der\t%s\n", csr);

	/*字符串 PEM编码 证书请求*/
	pBIO = BIO_new(BIO_s_mem());
	if (PEM_write_bio_X509_REQ(pBIO, pX509Req) != 1) {
		ZF_LOGE("X509_REQ error");
		goto free_all;
	}
	BIO_get_mem_ptr(pBIO, &pBMem);
	if (csr)
	{
		memcpy(csr, pBMem->data, pBMem->length);
	}
	*csrLen = pBMem->length;
	BIO_free(pBIO);

	/*生成文件 DER编码 证书请求*/
	/* 生成的是无效文件,需要添加公钥生成x509证书才是有效的cer文件*/
	pBIO = BIO_new_file("pkcs10.der", "w");
	if (!pBIO)
	{
		ZF_LOGE("pkcs10.der pBIO error");
		goto free_all;
	}
	iRV = i2d_X509_REQ_bio(pBIO, pX509Req);// 功能与i2d_X509_REQ_fp相同
	if (iRV != 1)
	{
		ZF_LOGE("pkcs10.der error");
		goto free_all;
	}
	BIO_free(pBIO);

	/*生成文件 PEM编码 证书请求*/
	pBIO = BIO_new_file("pkcs10.pem", "w");
	if (!pBIO)
	{
		ZF_LOGE("pkcs10.pem pBIO error");
		goto free_all;
	}
	if (PEM_write_bio_X509_REQ(pBIO, pX509Req) != 1) {
		ZF_LOGE("X509_REQ error");
		goto free_all;
	}
free_all:
	BIO_free(pBIO);
	X509_REQ_free(pX509Req);
	RSA_free(pRSA);
	return 0;
}

