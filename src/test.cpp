#include "interface.h"
#include <iostream>

using namespace std;

int main(int argc, char** argv)
{
	char chDN[255] = "CN=必填_小路人,O=小路人_O,OU=小路人_OU,ST=小路人_ST,L=小路人_L,C=CN";
	char c_csr[4096] = { 0 };
	int csr_len = 0;
	cout << "genRsaCsr() return  " << genRsaCsr(chDN, c_csr, &csr_len) << "\n"<< c_csr << endl;
    return 0;
}
