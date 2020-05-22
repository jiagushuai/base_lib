#include "interface.h"
#include <iostream>

using namespace std;

int main(int argc, char** argv)
{
	const char * param = "Ğ¡Â·ÈË";
	int length = strlen(param);
	char *cResult = test1(length, param);
	cout << "test1(" << length <<","<< param <<") = " << cResult << endl;
	int rv = 0;
	rv = test2(cResult);
	cout << "test2("<< cResult <<") = " << rv << endl;
	delete cResult;
	cResult;
    return 0;
}
