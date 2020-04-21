#include "interface.h"
#include "rsaLib.h"
#include <stdio.h>
rsaLib rsa;
int add(int a, int b)
{
	char chDN[255] = "CN=必填_小路人,O=小路人_O,OU=小路人_OU,ST=小路人_ST,L=小路人_L,C=CN";
	char c_csr[4096] = { 0 };
	int csr_len = 0;
	int rv = rsa.genRsaCsr(chDN, c_csr,&csr_len);
	printf("csr\t%s\n", c_csr);
    return a + b;
}
