//
//  base64.hpp
//
//  Created by hjl on 2018/12/4.
//
#ifdef __cplusplus
extern "C" {
#endif
    
#if defined(_WIN32)
#   define __export         __declspec(dllexport)
#elif defined(__GNUC__) && ((__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
#   define __export         __attribute__((visibility("default")))
#else
#   define __export
#endif
  
	__export int getEncodeLen(int MaxLen, unsigned char *pbOutData);
	__export int getDecodeLen(unsigned char *pbOutData);
	__export unsigned char *base64_encode(int MaxLen, unsigned char *str);
    __export unsigned char *base64_decode(unsigned char *code);
    
    
#ifdef __cplusplus
}
#endif




