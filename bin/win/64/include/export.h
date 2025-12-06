#ifndef EXPORT_H
#define EXPORT_H

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__EMSCRIPTEN__)
    #include <emscripten/emscripten.h>
    #define EXPORT EMSCRIPTEN_KEEPALIVE

#elif defined(_WIN32) || defined(_WIN64)
    #define EXPORT __declspec(dllexport)

#elif defined(__CYGWIN__)
    #define EXPORT __attribute__((dllexport))

#elif defined(__ANDROID__) \
   || defined(__linux__)    \
   || defined(__unix__)     \
   || defined(__APPLE__)
    #define EXPORT __attribute__((visibility("default")))

#else
    #define EXPORT   /* fallback: enjoy the chaos */
#endif

#if defined(__cplusplus)
}
#endif

#endif /* EXPORT_H */
