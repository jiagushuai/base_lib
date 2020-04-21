#include "strnormalize.h"
#include "base64.h"
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "zf_log.h"
#include "zf_file_output.h"

#include <string>
#include <vector>

typedef std::string string;

int split(const string& str, std::vector<string>& ret_, string sep)
{
	if (str.empty())
	{
		return 0;
	}

	string tmp;
	string::size_type pos_begin = str.find_first_not_of(sep);
	string::size_type comma_pos = 0;

	while (pos_begin != string::npos)
	{
		comma_pos = str.find(sep, pos_begin);
		if (comma_pos != string::npos)
		{
			tmp = str.substr(pos_begin, comma_pos - pos_begin);
			pos_begin = comma_pos + sep.length();
		}
		else
		{
			tmp = str.substr(pos_begin);
			pos_begin = comma_pos;
		}

		if (!tmp.empty())
		{
			ret_.push_back(tmp);
			tmp.clear();
		}
	}
	return 0;
}

int genX509NAME(const char * DN, X509_NAME *pX509Name)
{
	if (DN == NULL)
	{
		return -1;
	}
	if (pX509Name == NULL)
	{
		return -1;
	}
	/*用DN生成X509_NAME结构*/

	int					iRV = 0;
	std::vector<string> vctDNs;
	string				stDNs = DN;
	uint32_t			utf8buffer_len;
	uint32_t			gbkbuffer_len;
	char				*utf8buffer = NULL;

	split(stDNs, vctDNs, ",");
	str_normalize_init();
	for (int i = 0; i < (int)vctDNs.size(); i++)
	{
		std::vector<string> vctKVs;
		split(vctDNs[i], vctKVs, "=");
		if (vctKVs.size() != 2)
		{
			continue;
		}
		gbkbuffer_len = vctKVs[1].length();
		utf8buffer_len = gbkbuffer_len * 2 + 1;
		utf8buffer = new char[utf8buffer_len];
		if (NULL == utf8buffer)
			continue;
		memset(utf8buffer, 0, utf8buffer_len);
		iRV = gbk_to_utf8(vctKVs[1].c_str(), gbkbuffer_len, &utf8buffer, &utf8buffer_len);
		if (iRV == -1) {
			delete utf8buffer;
			utf8buffer = NULL;
			continue;
		}
		iRV = X509_NAME_add_entry_by_txt(pX509Name, vctKVs[0].c_str(), V_ASN1_UTF8STRING, (const unsigned char *)utf8buffer, -1, -1, 0);
	}
	delete[]utf8buffer;
	utf8buffer = NULL;
	return 0;
}

int genX509REQ(X509_NAME * pX509DN, EVP_PKEY *pEVPKey,X509_REQ  *pX509Req)
{
	int				iRV = 0;
	long            lVer = 3;
	const EVP_MD    *md = NULL;

	char szAltName[] = "DNS:www.gushuai.fun";
	char szComment[] = "Create by gushuai";
	char szKeyUsage[] = "digitalSignature, nonRepudiation";
	char szExKeyUsage[] = "serverAuth, clientAuth";
	char szBuf[255] = { 0 };
	unsigned char   mdout[1024];
	unsigned int    nLen, nModLen;

	iRV = X509_REQ_set_version(pX509Req, lVer);
	iRV = X509_REQ_set_subject_name(pX509Req, pX509DN);
	iRV = X509_REQ_set_pubkey(pX509Req, pEVPKey);

	/* attribute */
	strcpy(szBuf, szAltName);
	nLen = strlen(szBuf);
	iRV = X509_REQ_add1_attr_by_txt(pX509Req, "subjectAltName", V_ASN1_UTF8STRING, (const unsigned char *)szBuf, nLen);

	strcpy(szBuf, szKeyUsage);
	nLen = strlen(szBuf);
	iRV = X509_REQ_add1_attr_by_txt(pX509Req, "keyUsage", V_ASN1_UTF8STRING, (const unsigned char *)szBuf, nLen);

	strcpy(szBuf, szExKeyUsage);
	nLen = strlen(szBuf);
	iRV = X509_REQ_add1_attr_by_txt(pX509Req, "extendedKeyUsage", V_ASN1_UTF8STRING, (const unsigned char *)szBuf, nLen);

	strcpy(szBuf, szComment);
	nLen = strlen(szBuf);
	iRV = X509_REQ_add1_attr_by_txt(pX509Req, "nsComment", V_ASN1_UTF8STRING, (const unsigned char *)szBuf, nLen);

	md = EVP_sha256();
	iRV = X509_REQ_digest(pX509Req, md, mdout, &nModLen);
	iRV = X509_REQ_sign(pX509Req, pEVPKey, md);
	if (!iRV)
	{
		ZF_LOGE("genX509REQ X509_REQ_sign error");
		return -1;
	}
	iRV = X509_REQ_verify(pX509Req, pEVPKey);
	if (iRV<0)
	{
		ZF_LOGE("genX509REQ X509_REQ_verify error");
		return -1;
	}
	return 0;
}
//
//int genEcPubDER(EC_KEY *ec_key, unsigned  char * pubKeyBase64, int * pubLen)
//{
//	/* DER编码 pri*/
//	int             nLen = 0;
//	unsigned char   *pDer = NULL;
//	unsigned char   *p = NULL;
//
//	/* DER编码 pubkey*/
//	nLen = i2d_EC_PUBKEY(ec_key, NULL);
//	pDer = (unsigned char *)malloc(nLen);
//	p = pDer;//i2o_ECPublicKey
//	nLen = i2d_EC_PUBKEY(ec_key, &p);
//	memcpy(pubKeyBase64, pDer, nLen);
//	*pubLen = nLen;
//	free(pDer);
//
//	//nLen = i2o_ECPublicKey(ec_key, NULL);
//	//pDer = (unsigned char *)malloc(nLen);
//	//p = pDer;
//	//nLen = i2o_ECPublicKey(ec_key, &p);
//	//memcpy(csr, pDer, nLen);
//	//*csrLen = nLen;
//	//free(pDer);
//	return 0;
//}
//int genCsrDER(X509_REQ  *pX509Req, unsigned char * csr, int * csrLen)
//{
//	/* DER编码 pri*/
//	BIO             *pPemBIO = NULL;
//	BUF_MEM         *pBMem = NULL;
//	int             iRV = 0, nLen = 0;
//	unsigned char   *pDer = NULL;
//	unsigned char   *p = NULL;
//	
//	/* DER编码 pkcs10*/
//	nLen = i2d_X509_REQ(pX509Req, NULL);
//	pDer = (unsigned char *)malloc(nLen);
//	p = pDer;
//	nLen = i2d_X509_REQ(pX509Req, &p);
//	memcpy(csr, pDer, nLen);
//	*csrLen = nLen;
//	free(pDer);
//	return 0;
//}
//int genPriPkcs8(EVP_PKEY *pEVPKey, char * pfxPwd,  unsigned char * priKeyBase64, int * priLen)
//{
//	/* DER编码 pri*/
//	BIO             *pPemBIO = NULL;
//	BUF_MEM         *pBMem = NULL;
//	int             iRV = 0;
//	pPemBIO = BIO_new(BIO_s_mem());
//	pem_password_cb *passphrase;
//	// encrypt the the private key with the passphrase and put it in the BIO in DER format 
//	iRV = i2d_PKCS8PrivateKey_bio(pPemBIO, pEVPKey, EVP_des_ede3_cbc(), pfxPwd, strlen(pfxPwd), passphrase, pfxPwd);
//	BIO_get_mem_ptr(pPemBIO, &pBMem);
//	if (priKeyBase64)
//	{
//		memcpy(priKeyBase64, pBMem->data, pBMem->length);
//	}
//	*priLen = pBMem->length;
//	BIO_free(pPemBIO);
//	return 0;
//}
//
//int genEcPubPemFile(EC_KEY *ec_key, unsigned  char * pubKeyBase64, int * pubLen)
//{
//	BIO             *pBIO = NULL;
//	BIO             *pPemBIO = NULL;
//	BUF_MEM         *pBMem = NULL;
//	int             nLen = 0;
//
//	/* PEM编码 证书请求*/
//	pBIO = BIO_new_file("pubKey.pem", "w");
//	if (PEM_write_bio_EC_PUBKEY(pBIO, ec_key) != 1) {
//		ZF_LOGE("EC_PUBKEY error");
//		BIO_free(pBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_free(pBIO);
//	pPemBIO = BIO_new(BIO_s_mem());
//	if (PEM_write_bio_EC_PUBKEY(pPemBIO, ec_key) != 1) {
//		ZF_LOGE("EC_PUBKEY error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_get_mem_ptr(pPemBIO, &pBMem);
//	if (pubKeyBase64)
//	{
//		memcpy(pubKeyBase64, pBMem->data, pBMem->length);
//	}
//	*pubLen = pBMem->length;
//	BIO_free(pPemBIO);
//	return 0;
//}
//
//int genRsaPubPemFile(RSA *pRSA, unsigned  char * pubKeyBase64, int * pubLen)
//{
//	BIO             *pBIO = NULL;
//	BIO             *pPemBIO = NULL;
//	BUF_MEM         *pBMem = NULL;
//	int             nLen = 0;
//
//	/* PEM编码 证书请求*/
//	pBIO = BIO_new_file("pubKey.pem", "w");
//	if (PEM_write_bio_RSA_PUBKEY(pBIO, pRSA) != 1) {
//		ZF_LOGE("RSA_PUBKEY error");
//		BIO_free(pBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_free(pBIO);
//	pPemBIO = BIO_new(BIO_s_mem());
//	if (PEM_write_bio_RSA_PUBKEY(pPemBIO, pRSA) != 1) {
//		ZF_LOGE("RSA_PUBKEY error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_get_mem_ptr(pPemBIO, &pBMem);
//	if (pubKeyBase64)
//	{
//		memcpy(pubKeyBase64, pBMem->data, pBMem->length);
//	}
//	*pubLen = pBMem->length;
//	BIO_free(pPemBIO);
//	return 0;
//}
//
//int genPriPemFile(EVP_PKEY *pEVPKey, char * pfxPwd, unsigned char * priKeyBase64, int * priLen)
//{
//	BIO             *pBIO = NULL;
//	BIO             *pPemBIO = NULL;
//	BUF_MEM         *pBMem = NULL;
//	int             iRV = 0,nLen = 0;
//
//	/* PEM编码 证书请求*/
//	pBIO = BIO_new_file("priKey.pem", "w");
//	iRV = PEM_write_bio_PKCS8PrivateKey(pBIO, pEVPKey, EVP_des_ede3_cbc(), NULL, 0, 0, pfxPwd);
//	if (iRV != 1) {
//		ZF_LOGE("PKCS8PrivateKey error");
//		BIO_free(pBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_free(pBIO);
//	pPemBIO = BIO_new(BIO_s_mem());
//	iRV = PEM_write_bio_PKCS8PrivateKey(pPemBIO, pEVPKey, EVP_des_ede3_cbc(), NULL, 0, 0, pfxPwd);
//	if (iRV != 1) {
//		ZF_LOGE("PKCS8PrivateKey error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_get_mem_ptr(pPemBIO, &pBMem);
//	if (priKeyBase64)
//	{
//		memcpy(priKeyBase64, pBMem->data, pBMem->length);
//	}
//	*priLen = pBMem->length;
//	BIO_free(pPemBIO);
//	return 0;
//}
//int genCsrPemFile(X509_REQ  *pX509Req, unsigned char * csr, int * csrLen)
//{
//	BIO             *pBIO = NULL;
//	BIO             *pPemBIO = NULL;
//	BUF_MEM         *pBMem = NULL;
//	int             nLen = 0;
//
//	/* PEM编码 证书请求*/
//	pBIO = BIO_new_file("pkcs10.pem", "w");
//	if (PEM_write_bio_X509_REQ(pBIO, pX509Req) != 1) {
//		ZF_LOGE("X509_REQ error");
//		BIO_free(pBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_free(pBIO);
//	pPemBIO = BIO_new(BIO_s_mem());
//	if (PEM_write_bio_X509_REQ(pPemBIO, pX509Req) != 1) {
//		ZF_LOGE("X509_REQ error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_EXECL_ERR;
//	}
//	BIO_get_mem_ptr(pPemBIO, &pBMem);
//	if (csr)
//	{
//		memcpy(csr, pBMem->data, pBMem->length);
//	}
//	*csrLen = pBMem->length;
//	BIO_free(pPemBIO);
//	return 0;
//}
//
//int readPriDER(EC_KEY *ec_key, char * keyPwd, unsigned char * priKeyBase64)
//{
//	EVP_PKEY	*pEVPKey = NULL;
//	BIO			*pPemBIO = NULL;
//	pPemBIO = BIO_new_mem_buf(priKeyBase64, -1);
//	if (NULL == pPemBIO) {
//		ZF_LOGE("signByPfx priKeyBase64 toBio error");
//		return SAR_PARAM_PARSE_ERR;
//	}
//	pEVPKey = EVP_PKEY_new();
//	d2i_PKCS8PrivateKey_bio(pPemBIO, &pEVPKey, NULL, keyPwd);
//	ec_key = EVP_PKEY_get1_EC_KEY(pEVPKey);
//	if (ec_key == NULL) {
//		return SAR_PARAM_PARSE_ERR;
//	}
//	return 0;
//}
//
//int readEccPriPEM(EC_KEY **ec_key, char * keyPwd, unsigned char * priKeyBase64)
//{
//	EVP_PKEY	*pEVPKey = NULL;
//	BIO			*pPemBIO = NULL;
//
//	pPemBIO = BIO_new_mem_buf(priKeyBase64, -1);
//	if (NULL == pPemBIO) {
//		ZF_LOGE("signByPfx priKeyBase64 toBio error");
//		return SAR_PARAM_PARSE_ERR;
//	}
//	pEVPKey = EVP_PKEY_new();
//	PEM_read_bio_PrivateKey(pPemBIO, &pEVPKey, NULL, keyPwd);
//	*ec_key = EVP_PKEY_get1_EC_KEY(pEVPKey);
//	if (*ec_key == NULL) {
//		ZF_LOGE("read PrivateKey error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_PARSE_ERR;
//	}
//	return 0;
//}
//
//
//int readRsaPriPEM(RSA **rsa, char * keyPwd, unsigned char * priKeyBase64)
//{
//	EVP_PKEY	*pEVPKey = NULL;
//	BIO			*pPemBIO = NULL;
//
//	pPemBIO = BIO_new_mem_buf(priKeyBase64, -1);
//	if (NULL == pPemBIO) {
//		ZF_LOGE("signByPfx priKeyBase64 toBio error");
//		return SAR_PARAM_PARSE_ERR;
//	}
//	pEVPKey = EVP_PKEY_new();
//	PEM_read_bio_PrivateKey(pPemBIO, &pEVPKey, NULL, keyPwd);
//	*rsa = EVP_PKEY_get1_RSA(pEVPKey);
//	if (*rsa == NULL) {
//		ZF_LOGE("read PrivateKey error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_PARSE_ERR;
//	}
//	return 0;
//}
//int readPriPemTPkey(EVP_PKEY **pEVPKey, char * keyPwd, unsigned char * priKeyBase64)
//{
//	BIO			*pPemBIO = NULL;
//	pPemBIO = BIO_new_mem_buf(priKeyBase64, -1);
//	if (NULL == pPemBIO) {
//		ZF_LOGE("signByPfx priKeyBase64 toBio error");
//		return SAR_PARAM_PARSE_ERR;
//	}
//	PEM_read_bio_PrivateKey(pPemBIO, pEVPKey, NULL, keyPwd);
//	if (*pEVPKey == NULL) {
//		ZF_LOGE("read PrivateKey error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_PARSE_ERR;
//	}
//	BIO_free(pPemBIO);
//	return 0;
//}
//int readRsaPubPEM(RSA **rsa, unsigned char * base64)
//{
//	EVP_PKEY	*pEVPKey = NULL;
//	BIO			*pPemBIO = NULL;
//
//	pPemBIO = BIO_new_mem_buf(base64, -1);
//	if (NULL == pPemBIO) {
//		ZF_LOGE("signByPfx priKeyBase64 toBio error");
//		return SAR_PARAM_PARSE_ERR;
//	}
//	*rsa = PEM_read_bio_RSA_PUBKEY(pPemBIO, rsa, NULL, NULL);
//	if (*rsa == NULL) {
//		ZF_LOGE("read RSA_PUBKEY error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_PARSE_ERR;
//	}
//	return 0;
//}
//
//int readEccPubPEM(EC_KEY **ec_key, unsigned char * base64)
//{
//	BIO			*pPemBIO = NULL;
//	pPemBIO = BIO_new_mem_buf(base64, -1);
//	if (NULL == pPemBIO) {
//		ZF_LOGE("signByPfx EC_PUBKEY toBio error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_PARSE_ERR;
//	}
//	*ec_key = PEM_read_bio_EC_PUBKEY(pPemBIO, ec_key, NULL, NULL);
//	if (*ec_key == NULL) {
//		ZF_LOGE("read EC_PUBKEY error");
//		BIO_free(pPemBIO);
//		return SAR_PARAM_PARSE_ERR;
//	}
//	BIO_free(pPemBIO);
//	return 0;
//}
//
//int readRsaCerPEM(RSA **rsa, unsigned char * base64)
//{
//	EVP_PKEY	*pEVPKey = NULL;
//	BIO			*pPemBIO = NULL;
//	X509		*x509;
//	int			rv = 0;
//	pPemBIO = BIO_new_mem_buf(base64, -1);
//	if (NULL == pPemBIO) {
//		return SAR_PARAM_PARSE_ERR;
//	}
//	x509 = PEM_read_bio_X509(pPemBIO, NULL, NULL, NULL);
//	if (x509 == NULL) {
//		rv = SAR_PARAM_PARSE_ERR;
//		goto free;
//	}
//	/* 02：分解X509结构得到EVP_PKEY */
//	pEVPKey = X509_get_pubkey(x509);
//	if (NULL == pEVPKey) {
//		rv = SAR_PARAM_PARSE_ERR;
//		goto free;
//	}
//	/* 03：EVP_PKEY转换成RSA的KEY */
//	*rsa = EVP_PKEY_get1_RSA(pEVPKey);
//	if (NULL == *rsa) {
//		ZF_LOGE("verifyByCer rsa  error");
//		rv = SAR_PARAM_PARSE_ERR;
//		goto free;
//	}
//free:
//	BIO_free(pPemBIO);
//	return rv;
//}
//
//int readCerPEM(X509 **x509, char * base64)
//{
//	EVP_PKEY	*pEVPKey = NULL;
//	BIO			*pPemBIO = NULL;
//	int			rv = 0;
//	pPemBIO = BIO_new_mem_buf(base64, -1);
//	if (NULL == pPemBIO) {
//		return SAR_PARAM_PARSE_ERR;
//	}
//	*x509 = PEM_read_bio_X509(pPemBIO, NULL, NULL, NULL);
//	if (*x509 == NULL) {
//		rv = SAR_PARAM_PARSE_ERR;
//		goto free;
//	}
//free:
//	BIO_free(pPemBIO);
//	return rv;
//}
//
//int readEccCerPEM(EC_KEY **ec_key, unsigned char * base64)
//{
//	EVP_PKEY	*pEVPKey = NULL;
//	BIO			*pPemBIO = NULL;
//	X509		*x509;
//	int			rv = 0;
//	pPemBIO = BIO_new_mem_buf(base64, -1);
//	if (NULL == pPemBIO) {
//		return SAR_PARAM_PARSE_ERR;
//	}
//	x509 = PEM_read_bio_X509(pPemBIO, NULL, NULL, NULL);
//	if (x509 == NULL) {
//		rv = SAR_PARAM_PARSE_ERR;
//		goto free;
//	}
//	/* 02：分解X509结构得到EVP_PKEY */
//	pEVPKey = X509_get_pubkey(x509);
//	if (NULL == pEVPKey) {
//		rv = SAR_PARAM_PARSE_ERR;
//		goto free;
//	}
//	/* 03：EVP_PKEY转换成RSA的KEY */
//	*ec_key = EVP_PKEY_get1_EC_KEY(pEVPKey);
//	if (NULL == *ec_key) {
//		rv = SAR_PARAM_PARSE_ERR;
//		goto free;
//	}
//free:
//	BIO_free(pPemBIO);
//	return rv;
//}
//
//int getDN(X509_NAME* pName, char *lpValue, char * key)
//{
//	char csName[MAX_DN_SUB_SIZE*ENTRY_COUNT] = { 0 };
//	char csBuf[MAX_DN_SUB_SIZE] = { 0 };
//	uint32_t len;
//	uint32_t gbkbuffer_len;
//	str_normalize_init();
//	int iLen = 0;
//	int num = 0;
//	while (key != NULL) {//找到对应如CN的序号
//		if (strcmp(nids[num].name, key) == 0) {
//			break;
//		}
//		if (num >ENTRY_COUNT) {
//			break;
//		}
//		num++;
//	}
//	for (int i = num; i < ENTRY_COUNT; i++) {
//		memset(csBuf, 0, MAX_DN_SUB_SIZE);
//		iLen = X509_NAME_get_text_by_NID(pName, nids[i].key, csBuf, MAX_DN_SUB_SIZE);
//
//		len = strlen(csBuf);
//		gbkbuffer_len = len * 3 + 1;
//		char *gbkbuffer = (char *)malloc(gbkbuffer_len);
//		memset(gbkbuffer, 0, gbkbuffer_len);
//		utf8_to_gbk(csBuf, len, &gbkbuffer, &gbkbuffer_len);
//		strcat_s(csName, 1024, nids[i].name);
//		strcat_s(csName, 1024, "=");
//		strcat_s(csName, 1024, gbkbuffer);
//
//		if (key != NULL) {//传入key存在则找到该值就break出来啦
//			delete[]gbkbuffer;
//			break;
//		}
//		if (i != ENTRY_COUNT - 1)
//			strcat_s(csName, 1024, ",");
//		delete[]gbkbuffer;
//	}
//	if (key != NULL) {
//		char * msg = csName;
//		getKeyValue(msg, key, csName, ",");
//	}
//	if (lpValue)
//		strcpy_s(lpValue, strlen(csName) + 1, csName);
//	return 0;
//}
//void printHex(unsigned char *md, int len)
//{
//	int i = 0;
//	for (i = 0; i<len; i++) {
//		printf("%02x", md[i]);
//	}
//	printf("\n");
//}