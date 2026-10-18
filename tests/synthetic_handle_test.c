#include <stdio.h>
#include "../src/synthetic_handle.c"

int main(void)
{
    /* Explicit independently readable contract cases; no original-game oracle. */
    const struct {u32 h,n; u16 g; u8 live; int want;} cases[] = {
        {0,1,0,1,1}, {0,1,0,0,0}, {0,0,0,1,0}, {0,65536,0,1,0},
        {0xffffffffu,65535,65535,1,0}, {0x00010002,3,1,1,1},
        {0x00010003,3,1,1,0}, {0x00010002,3,2,1,0},
        {0xffff0000u,1,65535,1,1}, {0x0000fffe,65535,0,255,1},
        {0x0000ffff,65535,0,1,0}, {0x80000000u,1,32768,1,1},
        {0,0xffffffffu,0,1,0}, {0x7fff0000u,1,32767,128,1}
    };
    unsigned count = sizeof(cases)/sizeof(cases[0]);
    for (unsigned i=0;i<count;++i) {
        int a=synthetic_handle_matches(cases[i].h,cases[i].n,cases[i].g,cases[i].live);
        int b=synthetic_handle_matches_stdcall(cases[i].h,cases[i].n,cases[i].g,cases[i].live);
        if (a != cases[i].want || b != cases[i].want) {
            fprintf(stderr,"case %u failed\n",i); return 1;
        }
    }
    printf("synthetic handle contract: %u cases passed (two wrappers)\n",count);
    return 0;
}
