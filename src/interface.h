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

/*! calculate add(a, b) 
 *
 * @param a     the first argument
 * @param b     the second argument
 *
 * @return      the result
 */
__export int    add(int a, int b);
__export int	genRsaCsr(const char * DN, char * csr, int *csrLen);
__export int	genRsaKey(char * priKey, char * priPwd, char * pubKey);

#ifdef __cplusplus
}
#endif
