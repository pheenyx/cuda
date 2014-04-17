#include "cudaDES.h"


// Regular implementation

unsigned char* plain;
unsigned char* cipher;
unsigned char* key;
int isSerial = 0;
int verbose = 0;

void des_key_set_parity( unsigned char key[DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < DES_KEY_SIZE; i++ )
        key[i] = odd_parity_table[key[i] / 2];
}

/*
 * Check the given key's parity, returns 1 on failure, 0 on SUCCESS
 */
int des_key_check_key_parity( const unsigned char key[DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < DES_KEY_SIZE; i++ )
        if ( key[i] != odd_parity_table[key[i] / 2] )
            return( 1 );

    return( 0 );
}


static void des_setkey( uint32_t SK[32], const unsigned char key[DES_KEY_SIZE] )
{
    int i;
    uint32_t X, Y, T;

    GET_UINT32_BE( X, key, 0 );
    GET_UINT32_BE( Y, key, 4 );

    /*
     * Permuted Choice 1
     */
    T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
    T =  ((Y      ) ^ X) & 0x10101010;  X ^= T; Y ^= (T      );

    X =   (LHs[ (X      ) & 0xF] << 3) | (LHs[ (X >>  8) & 0xF ] << 2)
        | (LHs[ (X >> 16) & 0xF] << 1) | (LHs[ (X >> 24) & 0xF ]     )
        | (LHs[ (X >>  5) & 0xF] << 7) | (LHs[ (X >> 13) & 0xF ] << 6)
        | (LHs[ (X >> 21) & 0xF] << 5) | (LHs[ (X >> 29) & 0xF ] << 4);

    Y =   (RHs[ (Y >>  1) & 0xF] << 3) | (RHs[ (Y >>  9) & 0xF ] << 2)
        | (RHs[ (Y >> 17) & 0xF] << 1) | (RHs[ (Y >> 25) & 0xF ]     )
        | (RHs[ (Y >>  4) & 0xF] << 7) | (RHs[ (Y >> 12) & 0xF ] << 6)
        | (RHs[ (Y >> 20) & 0xF] << 5) | (RHs[ (Y >> 28) & 0xF ] << 4);

    X &= 0x0FFFFFFF;
    Y &= 0x0FFFFFFF;

    /*
     * calculate subkeys
     */
    for( i = 0; i < 16; i++ )
    {
        if( i < 2 || i == 8 || i == 15 )
        {
            X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
            Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
        }
        else
        {
            X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
            Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
        }

        *SK++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
                | ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
                | ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
                | ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
                | ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
                | ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
                | ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
                | ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
                | ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
                | ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
                | ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

        *SK++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
                | ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
                | ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
                | ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
                | ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
                | ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
                | ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
                | ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
                | ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
                | ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
                | ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
    }
}

/*
 * DES key schedule (56-bit, encryption)
 */
int des_setkey_enc( des_context *ctx, const unsigned char key[DES_KEY_SIZE] )
{
    des_setkey( ctx->sk, key );

    return( 0 );
}

/*
 * DES key schedule (56-bit, decryption)
 */
int des_setkey_dec( des_context *ctx, const unsigned char key[DES_KEY_SIZE] )
{
    int i;

    des_setkey( ctx->sk, key );

    for( i = 0; i < 16; i += 2 )
    {
        SWAP( ctx->sk[i    ], ctx->sk[30 - i] );
        SWAP( ctx->sk[i + 1], ctx->sk[31 - i] );
    }

    return( 0 );
}


/*
 * DES-ECB block encryption/decryption
 */
int des_crypt_ecb( des_context *ctx,
                    const unsigned char input[8],
                    unsigned char output[8] )
{
    int i;
    uint32_t X, Y, T, *SK;

    SK = ctx->sk;

    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );

    DES_IP( X, Y );

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    DES_FP( Y, X );

    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );

    return( 0 );
}


__global__ void DESkernel(volatile int* keyfound, unsigned char* key, const unsigned char* plain, const unsigned char* cipher, int size)
{
    int tid = blockIdx.x*blockDim.x + threadIdx.x;
    int inc = blockDim.x * gridDim.x; //#threads * #blocks
    int debug = 0;
    *keyfound = 0;
    
/*    printf("plain kernel\n");
    displayData_cuda(plain, size);
    printf("key kernel\n");
    displayData_cuda(key, size);
    printf("cipher kernel\n");
    displayData_cuda(cipher, size);
*/    
    des_context my_ctx;
    unsigned char buf[8];
    unsigned char my_key[8];
    memcpy(my_key,key,size);

    //initalize offset for threads
    newKey_cuda(my_key, tid);
    
    while(debug<500000 &&  !(*keyfound))
    {
/*        if ( tid == 0 && debug % 100 == 0){
            printf("debug %i!!! found: %i tid:%i my key:%c %02x   %c %02x   %c %02x   %c %02x   \n",debug,*keyfound,tid,my_key[0],my_key[0],my_key[1],my_key[1],my_key[2],my_key[2],my_key[3],my_key[3]);
        }
*/
        des_setkey_enc_cuda ( &my_ctx, my_key);
        //printf("found: %i tid:%i my key:%c %02x   %c %02x   %c %02x   %c %02x   \n",*keyfound,tid,my_key[0],my_key[0],my_key[1],my_key[1],my_key[2],my_key[2],my_key[3],my_key[3]);

        des_crypt_ecb_cuda( &my_ctx, plain, buf );
        //printf("tid:%i my cipher:%c %02x   %c %02x   %c %02x   %c %02x  \n",tid,buf[0],buf[0],buf[1],buf[1],buf[2],buf[2],buf[3],buf[3]);

        if (equals_cuda(buf, cipher))
        {
            printf("!!! KEY FOUND (tid %i, loops %i) !!!\n",tid, debug);
            printf("tid:%i key:%c %02X   %c %02X   %c %02X   %c %02X   %c %02X   %c %02X   %c %02X   %c %02X   \n",tid,my_key[0],my_key[0],my_key[1],my_key[1],my_key[2],my_key[2],my_key[3],my_key[3],my_key[4],my_key[4],my_key[5],my_key[5],my_key[6],my_key[6],my_key[7],my_key[7]);
            *keyfound = 1;
            memcpy(key, my_key, size);
            //break;
        }
        
        newKey_cuda(my_key, inc);
        ++debug;
        
    }
}

__device__ void newKey_cuda(unsigned char* key, int inc)
{
    *(uint64_t *)key += inc;
}

__device__ int equals_cuda(const unsigned char* a, const unsigned char* b)
{
    return (*(uint64_t*)a == *(uint64_t*)b);
}

__device__ int des_setkey_enc_cuda( des_context *ctx, const unsigned char key[DES_KEY_SIZE] )
{
    des_setkey_cuda( ctx->sk, key );
    return( 0 );
}
 
__device__ static void des_setkey_cuda( uint32_t SK[32], const unsigned char key[DES_KEY_SIZE] )
{
    int i;
    uint32_t X, Y, T;
    /*
     * PC1: left and right halves bit-swap
     */
    const uint32_t LHs[16] =
    {
        0x00000000, 0x00000001, 0x00000100, 0x00000101,
        0x00010000, 0x00010001, 0x00010100, 0x00010101,
        0x01000000, 0x01000001, 0x01000100, 0x01000101,
        0x01010000, 0x01010001, 0x01010100, 0x01010101
    };

    const uint32_t RHs[16] =
    {
        0x00000000, 0x01000000, 0x00010000, 0x01010000,
        0x00000100, 0x01000100, 0x00010100, 0x01010100,
        0x00000001, 0x01000001, 0x00010001, 0x01010001,
        0x00000101, 0x01000101, 0x00010101, 0x01010101,
    };


    GET_UINT32_BE( X, key, 0 );
    GET_UINT32_BE( Y, key, 4 );

    /*
     * Permuted Choice 1
     */
    T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
    T =  ((Y      ) ^ X) & 0x10101010;  X ^= T; Y ^= (T      );

    X =   (LHs[ (X      ) & 0xF] << 3) | (LHs[ (X >>  8) & 0xF ] << 2)
        | (LHs[ (X >> 16) & 0xF] << 1) | (LHs[ (X >> 24) & 0xF ]     )
        | (LHs[ (X >>  5) & 0xF] << 7) | (LHs[ (X >> 13) & 0xF ] << 6)
        | (LHs[ (X >> 21) & 0xF] << 5) | (LHs[ (X >> 29) & 0xF ] << 4);

    Y =   (RHs[ (Y >>  1) & 0xF] << 3) | (RHs[ (Y >>  9) & 0xF ] << 2)
        | (RHs[ (Y >> 17) & 0xF] << 1) | (RHs[ (Y >> 25) & 0xF ]     )
        | (RHs[ (Y >>  4) & 0xF] << 7) | (RHs[ (Y >> 12) & 0xF ] << 6)
        | (RHs[ (Y >> 20) & 0xF] << 5) | (RHs[ (Y >> 28) & 0xF ] << 4);

    X &= 0x0FFFFFFF;
    Y &= 0x0FFFFFFF;

    /*
     * calculate subkeys
     */
    for( i = 0; i < 16; i++ )
    {
        if( i < 2 || i == 8 || i == 15 )
        {
            X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
            Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
        }
        else
        {
            X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
            Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
        }

        *SK++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
            | ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
            | ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
            | ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
            | ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
            | ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
            | ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
            | ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
            | ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
            | ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
            | ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

        *SK++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
            | ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
            | ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
            | ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
            | ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
            | ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
            | ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
            | ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
            | ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
            | ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
            | ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
    }
}

__device__ int des_crypt_ecb_cuda( des_context *ctx,
        const unsigned char input[8],
        unsigned char output[8] )
{
    int i;
    uint32_t X, Y, T, *SK;
    const uint32_t SB1[64] =
    {
        0x01010400, 0x00000000, 0x00010000, 0x01010404,
        0x01010004, 0x00010404, 0x00000004, 0x00010000,
        0x00000400, 0x01010400, 0x01010404, 0x00000400,
        0x01000404, 0x01010004, 0x01000000, 0x00000004,
        0x00000404, 0x01000400, 0x01000400, 0x00010400,
        0x00010400, 0x01010000, 0x01010000, 0x01000404,
        0x00010004, 0x01000004, 0x01000004, 0x00010004,
        0x00000000, 0x00000404, 0x00010404, 0x01000000,
        0x00010000, 0x01010404, 0x00000004, 0x01010000,
        0x01010400, 0x01000000, 0x01000000, 0x00000400,
        0x01010004, 0x00010000, 0x00010400, 0x01000004,
        0x00000400, 0x00000004, 0x01000404, 0x00010404,
        0x01010404, 0x00010004, 0x01010000, 0x01000404,
        0x01000004, 0x00000404, 0x00010404, 0x01010400,
        0x00000404, 0x01000400, 0x01000400, 0x00000000,
        0x00010004, 0x00010400, 0x00000000, 0x01010004
    };

    const uint32_t SB2[64] =
    {
        0x80108020, 0x80008000, 0x00008000, 0x00108020,
        0x00100000, 0x00000020, 0x80100020, 0x80008020,
        0x80000020, 0x80108020, 0x80108000, 0x80000000,
        0x80008000, 0x00100000, 0x00000020, 0x80100020,
        0x00108000, 0x00100020, 0x80008020, 0x00000000,
        0x80000000, 0x00008000, 0x00108020, 0x80100000,
        0x00100020, 0x80000020, 0x00000000, 0x00108000,
        0x00008020, 0x80108000, 0x80100000, 0x00008020,
        0x00000000, 0x00108020, 0x80100020, 0x00100000,
        0x80008020, 0x80100000, 0x80108000, 0x00008000,
        0x80100000, 0x80008000, 0x00000020, 0x80108020,
        0x00108020, 0x00000020, 0x00008000, 0x80000000,
        0x00008020, 0x80108000, 0x00100000, 0x80000020,
        0x00100020, 0x80008020, 0x80000020, 0x00100020,
        0x00108000, 0x00000000, 0x80008000, 0x00008020,
        0x80000000, 0x80100020, 0x80108020, 0x00108000
    };

    const uint32_t SB3[64] =
    {
        0x00000208, 0x08020200, 0x00000000, 0x08020008,
        0x08000200, 0x00000000, 0x00020208, 0x08000200,
        0x00020008, 0x08000008, 0x08000008, 0x00020000,
        0x08020208, 0x00020008, 0x08020000, 0x00000208,
        0x08000000, 0x00000008, 0x08020200, 0x00000200,
        0x00020200, 0x08020000, 0x08020008, 0x00020208,
        0x08000208, 0x00020200, 0x00020000, 0x08000208,
        0x00000008, 0x08020208, 0x00000200, 0x08000000,
        0x08020200, 0x08000000, 0x00020008, 0x00000208,
        0x00020000, 0x08020200, 0x08000200, 0x00000000,
        0x00000200, 0x00020008, 0x08020208, 0x08000200,
        0x08000008, 0x00000200, 0x00000000, 0x08020008,
        0x08000208, 0x00020000, 0x08000000, 0x08020208,
        0x00000008, 0x00020208, 0x00020200, 0x08000008,
        0x08020000, 0x08000208, 0x00000208, 0x08020000,
        0x00020208, 0x00000008, 0x08020008, 0x00020200
    };

    const uint32_t SB4[64] =
    {
        0x00802001, 0x00002081, 0x00002081, 0x00000080,
        0x00802080, 0x00800081, 0x00800001, 0x00002001,
        0x00000000, 0x00802000, 0x00802000, 0x00802081,
        0x00000081, 0x00000000, 0x00800080, 0x00800001,
        0x00000001, 0x00002000, 0x00800000, 0x00802001,
        0x00000080, 0x00800000, 0x00002001, 0x00002080,
        0x00800081, 0x00000001, 0x00002080, 0x00800080,
        0x00002000, 0x00802080, 0x00802081, 0x00000081,
        0x00800080, 0x00800001, 0x00802000, 0x00802081,
        0x00000081, 0x00000000, 0x00000000, 0x00802000,
        0x00002080, 0x00800080, 0x00800081, 0x00000001,
        0x00802001, 0x00002081, 0x00002081, 0x00000080,
        0x00802081, 0x00000081, 0x00000001, 0x00002000,
        0x00800001, 0x00002001, 0x00802080, 0x00800081,
        0x00002001, 0x00002080, 0x00800000, 0x00802001,
        0x00000080, 0x00800000, 0x00002000, 0x00802080
    };

    const uint32_t SB5[64] =
    {
        0x00000100, 0x02080100, 0x02080000, 0x42000100,
        0x00080000, 0x00000100, 0x40000000, 0x02080000,
        0x40080100, 0x00080000, 0x02000100, 0x40080100,
        0x42000100, 0x42080000, 0x00080100, 0x40000000,
        0x02000000, 0x40080000, 0x40080000, 0x00000000,
        0x40000100, 0x42080100, 0x42080100, 0x02000100,
        0x42080000, 0x40000100, 0x00000000, 0x42000000,
        0x02080100, 0x02000000, 0x42000000, 0x00080100,
        0x00080000, 0x42000100, 0x00000100, 0x02000000,
        0x40000000, 0x02080000, 0x42000100, 0x40080100,
        0x02000100, 0x40000000, 0x42080000, 0x02080100,
        0x40080100, 0x00000100, 0x02000000, 0x42080000,
        0x42080100, 0x00080100, 0x42000000, 0x42080100,
        0x02080000, 0x00000000, 0x40080000, 0x42000000,
        0x00080100, 0x02000100, 0x40000100, 0x00080000,
        0x00000000, 0x40080000, 0x02080100, 0x40000100
    };

    const uint32_t SB6[64] =
    {
        0x20000010, 0x20400000, 0x00004000, 0x20404010,
        0x20400000, 0x00000010, 0x20404010, 0x00400000,
        0x20004000, 0x00404010, 0x00400000, 0x20000010,
        0x00400010, 0x20004000, 0x20000000, 0x00004010,
        0x00000000, 0x00400010, 0x20004010, 0x00004000,
        0x00404000, 0x20004010, 0x00000010, 0x20400010,
        0x20400010, 0x00000000, 0x00404010, 0x20404000,
        0x00004010, 0x00404000, 0x20404000, 0x20000000,
        0x20004000, 0x00000010, 0x20400010, 0x00404000,
        0x20404010, 0x00400000, 0x00004010, 0x20000010,
        0x00400000, 0x20004000, 0x20000000, 0x00004010,
        0x20000010, 0x20404010, 0x00404000, 0x20400000,
        0x00404010, 0x20404000, 0x00000000, 0x20400010,
        0x00000010, 0x00004000, 0x20400000, 0x00404010,
        0x00004000, 0x00400010, 0x20004010, 0x00000000,
        0x20404000, 0x20000000, 0x00400010, 0x20004010
    };

    const uint32_t SB7[64] =
    {
        0x00200000, 0x04200002, 0x04000802, 0x00000000,
        0x00000800, 0x04000802, 0x00200802, 0x04200800,
        0x04200802, 0x00200000, 0x00000000, 0x04000002,
        0x00000002, 0x04000000, 0x04200002, 0x00000802,
        0x04000800, 0x00200802, 0x00200002, 0x04000800,
        0x04000002, 0x04200000, 0x04200800, 0x00200002,
        0x04200000, 0x00000800, 0x00000802, 0x04200802,
        0x00200800, 0x00000002, 0x04000000, 0x00200800,
        0x04000000, 0x00200800, 0x00200000, 0x04000802,
        0x04000802, 0x04200002, 0x04200002, 0x00000002,
        0x00200002, 0x04000000, 0x04000800, 0x00200000,
        0x04200800, 0x00000802, 0x00200802, 0x04200800,
        0x00000802, 0x04000002, 0x04200802, 0x04200000,
        0x00200800, 0x00000000, 0x00000002, 0x04200802,
        0x00000000, 0x00200802, 0x04200000, 0x00000800,
        0x04000002, 0x04000800, 0x00000800, 0x00200002
    };

    const uint32_t SB8[64] =
    {
        0x10001040, 0x00001000, 0x00040000, 0x10041040,
        0x10000000, 0x10001040, 0x00000040, 0x10000000,
        0x00040040, 0x10040000, 0x10041040, 0x00041000,
        0x10041000, 0x00041040, 0x00001000, 0x00000040,
        0x10040000, 0x10000040, 0x10001000, 0x00001040,
        0x00041000, 0x00040040, 0x10040040, 0x10041000,
        0x00001040, 0x00000000, 0x00000000, 0x10040040,
        0x10000040, 0x10001000, 0x00041040, 0x00040000,
        0x00041040, 0x00040000, 0x10041000, 0x00001000,
        0x00000040, 0x10040040, 0x00001000, 0x00041040,
        0x10001000, 0x00000040, 0x10000040, 0x10040000,
        0x10040040, 0x10000000, 0x00040000, 0x10001040,
        0x00000000, 0x10041040, 0x00040040, 0x10000040,
        0x10040000, 0x10001000, 0x10001040, 0x00000000,
        0x10041040, 0x00041000, 0x00041000, 0x00001040,
        0x00001040, 0x00040040, 0x10000000, 0x10041000
    };

    SK = ctx->sk;

    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );

    DES_IP( X, Y );

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    DES_FP( Y, X );

    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );

    return( 0 );
}

__device__ void displayData_cuda(const unsigned char* data, int size)
{
    for (int i = 0; i<size; ++i){
        printf("%c %02x\t",data[i],data[i]);
    }
    printf("\n");
}


void cudaFunction(unsigned char* key, const unsigned char* plain, const unsigned char* cipher, int size)
{   
    unsigned char* startkey = (unsigned char*)malloc(sizeof(unsigned char)*size);
    memcpy(startkey,key,size);

    cudaEvent_t start, stop;
    float elapsedTime;
    size_t real_size;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start,0);

    real_size = size * sizeof(unsigned char);
    unsigned char* d_key;
    unsigned char* d_plain;
    unsigned char* d_cipher;
    int* d_keyfound;

    //malloc device memory
    cudaMalloc(&d_key, real_size);
    checkCUDAError("cudaMalloc d_key");
    cudaMalloc(&d_plain, real_size);
    checkCUDAError("cudaMalloc d_plain");
    cudaMalloc(&d_cipher, real_size);
    checkCUDAError("cudaMalloc d_cipher");
    cudaMalloc(&d_keyfound, sizeof(int));
    checkCUDAError("cudaMalloc d_keyfound");

    //copy to device
    cudaMemcpy(d_key, key, real_size, cudaMemcpyHostToDevice);
    checkCUDAError("cudaMemcpy to device key");
    cudaMemcpy(d_plain, plain, real_size, cudaMemcpyHostToDevice);
    checkCUDAError("cudaMemcpy to device plain");
    cudaMemcpy(d_cipher, cipher, real_size, cudaMemcpyHostToDevice);
    checkCUDAError("cudaMemcpy to device cipher");

    
    //invoke kernel
    int numberBlocks = 64;     //64;
    int numberThreads = 32;    //32;
    //nt sharedSize = 3*real_size+sizeof(des_context);
    DESkernel<<<numberBlocks, numberThreads>>>(d_keyfound, d_key, d_plain, d_cipher, size);
    checkCUDAError("cudakernel call");
    
    //copy back to host
    cudaMemcpy(key, d_key, real_size, cudaMemcpyDeviceToHost);
    checkCUDAError("cudaMemcpy to horst cipher");

    //stop recorder and print time
    cudaEventRecord(stop,0);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsedTime,start,stop);
    printf("the result is :\n");
    if (equals(startkey,key)){
        printf("Key was not found\n");
    } else {
        displayData(key, size);
    }
    printf("Elapsed time is: %f\n",elapsedTime);
    //
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    // Free device memory
    cudaFree(d_key);
    cudaFree(d_plain);
    cudaFree(d_cipher);
    cudaFree(d_keyfound);
}

/*
 * Main routine
 */
int main( int argc, char** argv )
{
    des_context my_ctx;
    unsigned char buf[8];



/*    static unsigned char my_keys[8] =
    {
        0x60, 0x65, 0x79, 0x69, 0x65, 0x79, 0x6B, 0x65
    };
    static const unsigned char my_keys[24] =
    {
        0x6B, 0x65, 0x79, 0x6B, 0x65, 0x79, 0x6B, 0x65,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    };

    static const unsigned char my_plain[3][8] =
    {
        { 0x70, 0x6C, 0x61, 0x69, 0x6E, 0x31, 0x32, 0x33 },
        { 0x70, 0x6C, 0x61, 0x69, 0x6E, 0x34, 0x35, 0x36 },
        { 0x70, 0x6C, 0x61, 0x69, 0x6E, 0x37, 0x38, 0x39 }
    }; 
    
    static unsigned char my_cipher[8] =
    {
        0x1B, 0xCD, 0xB8, 0x89, 0x88, 0xE2, 0x02, 0x7F
    };   
*/
    printf("\n");


    parseArgs(argc,argv);


    if (verbose) {
        printf("start key:\n");
        displayData(key, 8);
        printf("plain:\n");
        displayData(plain, 8);
        printf("cipher:\n");
        displayData(cipher, 8);
    }
    //
    if(isSerial == 0)
    {
        printf("Running the CUDA implementation\n");
        cudaFunction(key,plain,cipher,8);
        //
    }
    else
    {
        printf("Running the serial implementation\n");
        cudaEvent_t start, stop;
        float elapsedTime;
        int size = 8;
        cudaEventCreate(&start);
        cudaEventCreate(&stop);

        cudaEventRecord(start,0);
        

        printf("=====START======\n");
        
        
        int keyfound = 0;
        long i = 0;

        printf("plain cpu\n");
        displayData(plain, size);
        printf("start key cpu\n");
        displayData(key, size);
        unsigned char my_key[8];
        memcpy(my_key,key,size);
        unsigned char found_key[8];
        memcpy(found_key, key, size);

        while(i<500000000 && !(keyfound))
        {
/*            if ( i % 100000 == 0){
                printf("loop %i!!! found: %i my key:%c %02x   %c %02x   %c %02x   %c %02x   \n",i,keyfound,my_key[0],my_key[0],my_key[1],my_key[1],my_key[2],my_key[2],my_key[3],my_key[3]);
            }
*/
            des_setkey_enc ( &my_ctx, my_key);


            des_crypt_ecb ( &my_ctx, plain, buf );

            if (equals(buf, cipher))
            {
                printf("!!! KEY FOUND (loop %li)!!!\n",i);
                keyfound = 1;
                memcpy(found_key, my_key, size);
                break;
            }

            newKey(my_key);
            ++i;

        }

        printf("=====END========\n");

        printf("\n");

        //stop recorder and print time
        cudaEventRecord(stop,0);
        cudaEventSynchronize(stop);
        cudaEventElapsedTime(&elapsedTime,start,stop);
        printf("the result is :\n");
        if (equals(key,found_key)){
            printf("Key was not found\n");
        } else {
            displayData(my_key, size);
        }
        printf("Elapsed time is: %f\n",elapsedTime);
        //
        cudaEventDestroy(start);
        cudaEventDestroy(stop);

    }
    return ( 0 );
}

void newKey(unsigned char* key)
{
    ++*(uint64_t *)key;
}

int equals(unsigned char* a, unsigned char* b)
{
    return (*(uint64_t*)a == *(uint64_t*)b);
}

void displayData(const unsigned char* data, int size)
{
    for (int i = 0; i<size; ++i){
        printf("%c %02x\t",data[i],data[i]);
    }
    printf("\n");
}

void checkCUDAError(const char *msg)
{
    cudaError_t err = cudaGetLastError();
    if( cudaSuccess != err) 
    {
        fprintf(stderr, "Cuda error: %s: %s.\n", msg, 
                cudaGetErrorString( err) );
        exit(EXIT_FAILURE);
    }                         
}

unsigned char* convert(char *s)
{
    unsigned char* val = (unsigned char*) malloc(strlen(s)/2);
    /* WARNING: no sanitization or error-checking whatsoever */
    for(int count = 0; count < sizeof(val)/sizeof(val[0]); count++) {
        sscanf(s, "%2hhx", &val[count]);
        s += 2 * sizeof(char);
    }
    return val;
}


void parseArgs(int argc, char** argv)
{
    char c;
    char* cipherIn;
    char* keyIn;
    int optionIndex = 0;
    struct option longOption[]=
    {
        {"plaintext",1,NULL,'p'},
        {"ciphertext",1,NULL,'c'},
        {"startkey",1,NULL,'k'},
        {"serial",1,NULL,'s'},
        {"verbose",1,NULL,'v'},
        {0,0,0,0}
    };
    if (argc < 6) 
    {
        printf("Wrong number of arguments\n");
        exit(1);
    }
    while((c=getopt_long(argc,argv,"p:c:k:sv",longOption,&optionIndex))!=-1)
    {
        switch(c)
        {
            case 'p':
                plain = (unsigned char*)strdup(optarg);
                break;
            case 'c':
                cipherIn = strdup(optarg);
                cipher = convert(cipherIn);
                break;
            case 'k':
                keyIn = strdup(optarg);
                key = convert(keyIn);
                break;
            case 's':
                isSerial = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                printf("Bad argument %c\n",c);
                exit(1);
        }
    }    
}

