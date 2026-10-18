/* Original synthetic ABI qualification fixture. NOT recovered Bully code.
 * Its generation/index split and sentinel are invented for tool qualification.
 * No headers or runtime are needed for freestanding i386 COFF compilation. */
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
_Static_assert(sizeof(u32) == 4 && sizeof(u16) == 2 && sizeof(u8) == 1,
               "fixture requires exact integer widths");

#if defined(_WIN32) && defined(__i386__)
# define CDECL __attribute__((cdecl))
# define STDCALL __attribute__((stdcall))
#else
# define CDECL
# define STDCALL
#endif

int CDECL synthetic_handle_matches(u32 handle, u32 capacity, u16 generation, u8 live)
{
    if (handle == 0xffffffffu || capacity == 0 || capacity > 65535u)
        return 0;
    return (handle & 65535u) < capacity && (handle >> 16) == generation && live != 0;
}

int STDCALL synthetic_handle_matches_stdcall(u32 h, u32 n, u16 g, u8 live)
{
    return synthetic_handle_matches(h, n, g, live);
}
