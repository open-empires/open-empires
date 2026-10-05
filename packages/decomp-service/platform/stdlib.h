#ifndef OE_STUB_STDLIB_H
#define OE_STUB_STDLIB_H
typedef unsigned long size_t;
#ifdef __cplusplus
extern "C" {
#endif
void *malloc(size_t); void free(void *); void *calloc(size_t, size_t);
void *realloc(void *, size_t);
int atoi(const char *); long atol(const char *); double atof(const char *);
int abs(int); long labs(long); void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
int rand(void); void srand(unsigned);
#ifdef __cplusplus
}
#endif
#endif
