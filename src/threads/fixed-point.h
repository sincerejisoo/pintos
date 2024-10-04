#ifndef THREADS_FIXED-POINT_H
#define THREADS_FIXED-POINT_H

#include <stdio.h>
#include <stdint.h>

long long int_to_fp(long long integer){
    return integer*16384;
}

long long fp_to_int_zero(long long fp){
    return (fp/16384);
}

long long fp_to_int_near(long long fp){
    if (fp>=0)
        return (fp+16384/2)/16384;
    else
        return (fp-16384/2)/16384;
}

long long mul_fp(long long fp1, long long fp2){
    fp1=(int64_t)fp1;
    return (fp1*fp2)/16384;
}

long long div_fp(long long fp1, long long fp2){
    fp1=(int64_t)fp1;
    return (fp1*16384)/fp2;
}

#endif