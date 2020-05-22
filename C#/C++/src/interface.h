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

	__export char *	test1(int length, const char * param);
	__export int	test2(char * cResult);

#ifdef __cplusplus
}
#endif
