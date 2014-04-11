/*  
*   Byte-oriented AES-256 implementation.
*   All lookup tables replaced with 'on the fly' calculations. 
*
*   Copyright (c) 2007-2009 Ilya O. Levin, http://www.literatecode.com
*   Other contributors: Hal Finney
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


This program is based in the source code from the above
authors, and is intended to pave half the way towards an
efficient CUDA implementation.

modified by: Joel Rodriguez-Ramirez.
joelrod@versamedium.com
July-10-2011.

In order to compile the program, do as follows:
go to:
 
cd ~/NVIDIA_GPU_Computing_SDK/C/src

of your cuda sdk directory (were the examples are):

mkdir aes256
cd aes256

copy this file and the following  Makefile to this location.

---start Makefile---
EXECUTABLE      := aes256_cuda
CUFILES         := aes256_cuda.cu
CCFILES         := 
include ../../common/common.mk
---finish Makefile---

My cuda card (GTS 450) has 4 SM's and 48 processors per SM
edit to fit your video GPU (lines 93-94 below)

#define SM_BLOCKS 4
#define THREADS 48

alternatively for a GeForce 9600 GT
#define SM_BLOCKS 8
#define THREADS 8

type

make
cp ../../bin/linux/release/aes256_cuda .

run as :
To encode:
 ./aes256_cuda input_file output_file  passwd.txt enc


To decode:
 ./aes256_cuda input_file output_file  passwd.txt dec

---my password file looks like---
~/NVIDIA_GPU_Computing_SDK/C/src/aes256# more passwd.txt 
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
~/NVIDIA_GPU_Computing_SDK/C/src/aes256#
*/

#include <stdlib.h>
#include <stdio.h>
#include<math.h>
#include<string.h>
#include "cuda.h"

#ifndef uint8_t
#define uint8_t  unsigned char
#endif



uint8_t postal[201326592]; 

extern "C"

#define SM_BLOCKS 4
#define THREADS 48

#define BLOCK_SIZE SM_BLOCKS
#define MODEL_SIZE 5000


#define CHECK_BANK_CONFLICTS 0
#if CHECK_BANK_CONFLICTS
#define Coef(i) cutilBankChecker(((uint8_t*)&coef[0]), (BLOCK_SIZE * i))
#define Coefinv(k) cutilBankChecker(((uint8_t*)&coefinv[0]), (BLOCK_SIZE * k))
#else
#define Coef(i) coef[i]
#define Coefinv(k) coefinv[k]
#endif


void process_chunk(int val_enc_dec, uint8_t *key_local, int num_blocks, int num_threads);
__device__ uint8_t rj_xtime(uint8_t x);
__device__ void aes_addRoundKey(uint8_t *buf_shar, uint8_t *key_shar, int g, int tx, int bx);
__device__ void aes_addRoundKey_cpy1(uint8_t *buf_shar, uint8_t *key_shar, uint8_t *enckey_shar,int g, int tx, int bx);
__device__ void aes_addRoundKey_cpy2(uint8_t *buf_shar, uint8_t *key_shar, uint8_t *deckey_shar,int g,int tx,int bx);
__device__ void aes_shiftRows(uint8_t *buf_shar, int g, int tx, int bx);
__device__ void aes_shiftRows_inv(uint8_t *buf_shar, int g, int tx, int bx);
__device__ void aes_mixColumns(uint8_t *buf_shar, int g, int tx, int bx);
__device__ void aes_mixColumns_inv(uint8_t *buf_shar, int g, int tx, int bx);
__device__ void aes256_done(uint8_t *key_shar, uint8_t *enckey_shar, uint8_t *deckey_shar,int g,int tx,int bx);
__device__ void aes256_init1(uint8_t *enckey_shar, uint8_t *deckey_shar, uint8_t *local_key,int g,int tx,int bx);

const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t sboxinv[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


/* -------------------------------------------------------------------------- */
__device__ uint8_t rj_xtime(uint8_t x) 
{
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
} /* rj_xtime */


/* -------------------------------------------------------------------------- */
__device__ void aes_addRoundKey(uint8_t *buf_shar, uint8_t *key_shar,int g, int tx, int bx, int rounds)
{

    register uint8_t i = 16;
    register int index_buf;
    register int index_key;
    
    index_buf=(g*16);
    index_key=(g*16);

    while (i--) buf_shar[index_buf+i] ^= key_shar[index_key+i];

} /* aes_addRoundKey */


/* -------------------------------------------------------------------------- */

__device__ void aes_addRoundKey_cpy1(uint8_t *buf_shar, uint8_t *key_shar, uint8_t *enckey_shar,int g, int tx, int bx, int rounds)
{
    register uint8_t i = 16;
    register int index_buf;
    register int index_key;
    
    index_buf=(g*16);
    index_key=(g*16);



   while (i--){  
  buf_shar[index_buf+i] ^= (key_shar[index_key+i] = enckey_shar[index_key+i]);
  key_shar[index_key+(16+i)] = enckey_shar[index_key+(16+i)];
              }
		
} /* aes_addRoundKey_cpy (buf, ctx->enckey, ctx->key)  (bx*THREADS*1024)+ */


/* -------------------------------------------------------------------------- */



__device__ void aes_addRoundKey_cpy2(uint8_t *buf_shar, uint8_t *key_shar, uint8_t *deckey_shar,int g, int tx, int bx, int rounds)
{
    register uint8_t i = 16;
    register int index_buf;
    register int index_key;
    
    index_buf=(g*16);
    index_key=(g*16);


   while (i--)  {
                key_shar[index_key+i] = deckey_shar[index_key+i];
                buf_shar[index_buf+i] ^= key_shar[index_key+i], 
                key_shar[index_key+(16+i)] = deckey_shar[index_key+(16+i)];
                 }
} /* aes_addRoundKey_cpy (buf, ctx->deckey, ctx->key)*/



/* -------------------------------------------------------------------------- */
__device__ void aes_shiftRows(uint8_t *buf_shar,  int g, int tx, int bx, int rounds)
{
    register uint8_t i,j; /* to make it potentially parallelable :) */
    register int index_buf;
    
    index_buf=(g*16);

    i = buf_shar[index_buf+1]; 
    buf_shar[index_buf+1] = buf_shar[index_buf+5]; 
    buf_shar[index_buf+5] = buf_shar[index_buf+9]; 
    buf_shar[index_buf+9] = buf_shar[index_buf+13]; 
    buf_shar[index_buf+13] = i;
    i = buf_shar[index_buf+10]; 
    buf_shar[index_buf+10] = buf_shar[index_buf+2]; 
    buf_shar[index_buf+2] = i;
    j = buf_shar[index_buf+3]; 
    buf_shar[index_buf+3] = buf_shar[index_buf+15]; 
    buf_shar[index_buf+15] = buf_shar[index_buf+11]; 
    buf_shar[index_buf+11] = buf_shar[index_buf+7]; 
    buf_shar[index_buf+7] = j;
    j = buf_shar[index_buf+14];
    buf_shar[index_buf+14] = buf_shar[index_buf+6]; 
    buf_shar[index_buf+6]  = j;




} /* aes_shiftRows */


/* -------------------------------------------------------------------------- */
__device__ void aes_shiftRows_inv(uint8_t *buf_shar,  int g, int tx, int bx, int rounds)
{
    register uint8_t i, j; /* same as above :) */
    register int index_buf;
    
    index_buf=(g*16);

    i = buf_shar[index_buf+1]; 
    buf_shar[index_buf+1] = buf_shar[index_buf+13]; 
    buf_shar[index_buf+13] = buf_shar[index_buf+9]; 
    buf_shar[index_buf+9] = buf_shar[index_buf+5]; 
    buf_shar[index_buf+5] = i;
    i = buf_shar[index_buf+2]; 
    buf_shar[index_buf+2] = buf_shar[index_buf+10]; 
    buf_shar[index_buf+10] = i;
    j = buf_shar[index_buf+3]; 
    buf_shar[index_buf+3] = buf_shar[index_buf+7]; 
    buf_shar[index_buf+7] = buf_shar[index_buf+11]; 
    buf_shar[index_buf+11] = buf_shar[index_buf+15]; 
    buf_shar[index_buf+15] = j;
    j = buf_shar[index_buf+6]; 
    buf_shar[index_buf+6] = buf_shar[index_buf+14]; 
    buf_shar[index_buf+14] = j;

} /* aes_shiftRows_inv */


/* -------------------------------------------------------------------------- */
__device__ void aes_mixColumns(uint8_t *buf_shar, int g, int tx, int bx, int rounds)
{
    register uint8_t i,a, b, c, d, e ;
    register int index_buf;
    
    index_buf=(g*16);

    for (i = 0; i < 16; i += 4)
    {
        a = buf_shar[index_buf+i]; 
	b = buf_shar[index_buf+(i+1)]; 
	c = buf_shar[index_buf+(i+2)]; 
	d = buf_shar[index_buf+(i+3)];
        e = a ^ b ^ c ^ d;
        buf_shar[index_buf+i] ^= e ^ rj_xtime(a^b);   
	buf_shar[index_buf+(i+1)] ^= e ^ rj_xtime(b^c);
        buf_shar[index_buf+(i+2)] ^= e ^ rj_xtime(c^d); 
	buf_shar[index_buf+(i+3)] ^= e ^ rj_xtime(d^a);
    }


} /* aes_mixColumns */


/* -------------------------------------------------------------------------- */
__device__ void aes_mixColumns_inv(uint8_t *buf_shar, int g, int tx, int bx, int rounds)
{
    register uint8_t i,a, b, c, d, e, x, y, z;
    register int index_buf;
    
    index_buf=(g*16);

    for (i = 0; i < 16; i += 4)
    {
        a = buf_shar[index_buf+i]; 
	b = buf_shar[index_buf+(i+1)]; 
	c = buf_shar[index_buf+(i+2)]; 
	d = buf_shar[index_buf+(i+3)];
        e = a ^ b ^ c ^ d;
        z = rj_xtime(e);
        x = e ^ rj_xtime(rj_xtime(z^a^c));  
	y = e ^ rj_xtime(rj_xtime(z^b^d));
        buf_shar[index_buf+i] ^= x ^ rj_xtime(a^b);   
	buf_shar[index_buf+(i+1)] ^= y ^ rj_xtime(b^c);
        buf_shar[index_buf+(i+2)] ^= x ^ rj_xtime(c^d); 
	buf_shar[index_buf+(i+3)] ^= y ^ rj_xtime(d^a);
    }

    
} /* aes_mixColumns_inv */

/* -------------------------------------------------------------------------- */

__device__ void aes256_init1(uint8_t *enckey_shar, uint8_t *deckey_shar, uint8_t *key_local, int g, int tx, int bx)
{
      int i;
    register int index_key;

    index_key=(g*16);      
            
      for (i = 0; i < 32; i++) {
       enckey_shar[index_key+i] = key_local[i];
       deckey_shar[index_key+i] = key_local[i];
    
       
				}
				
} /* aes256_init */



/* -------------------------------------------------------------------------- */
__device__ void aes256_done(uint8_t *key_shar, uint8_t *enckey_shar, uint8_t *deckey_shar, int g, int tx, int bx)
{
     int i;

    register int index_key;
    
    index_key=(g*16);


    for (i = 0; i < 32; i++){
 			    key_shar[index_key+i] = 0;
			    enckey_shar[index_key+i] = 0;
			    deckey_shar[index_key+i] = 0;
                             }

} /* aes256_done */



__global__ void aes256_enc_kernel(uint8_t *sbox, uint8_t *sboxinv, uint8_t *buf, uint8_t *key, uint8_t *enckey, uint8_t *deckey, uint8_t *local_key, int rounds)
{
    uint8_t  rcon;        
    int g,i,k,tx,bx; 
    register int index_buf, index_key;
    
    bx = blockIdx.x;
    tx = threadIdx.x;

    __shared__ uint8_t coef[256];

    for(int step22=0;step22<256;++step22){
    	Coef(step22)=sbox[step22];
    					 }
  

    register uint8_t buf_shar[512];
    
    for(int stepk=0;stepk<512;++stepk){
    	buf_shar[stepk]=buf[(rounds*SM_BLOCKS*THREADS)+(bx*THREADS*512)+(tx*512)+stepk];
    					      }
 
 
    register uint8_t key_shar[1024];
    
    for(int stepl=0;stepl<1024;++stepl){
    	key_shar[stepl]=key[(bx*THREADS*1024)+(tx*1024)+stepl];
    					      }


    register uint8_t enckey_shar[1024];
    
    for(int stepm=0;stepm<1024;++stepm){
    	enckey_shar[stepm]=enckey[(bx*THREADS*1024)+(tx*1024)+stepm];
    					      }


    register uint8_t deckey_shar[1024];
  
    for(int stepn=0;stepn<1024;++stepn){
      deckey_shar[stepn]=deckey[(bx*THREADS*1024)+(tx*1024)+stepn];
					    }

  
    __syncthreads();

		 
    uint8_t *rc;

    for(g = 0; g <32; g++){
    
    
    index_buf=(g*16);
    index_key=(g*16);
    
    
    
    aes256_init1(enckey_shar,deckey_shar,local_key,g,tx,bx);
    aes_addRoundKey_cpy1(buf_shar,key_shar,enckey_shar,g,tx,bx,rounds);
			
    for(i = 1, rcon = 1; i < 14; ++i)
    {
//        aes_subBytes(buf,sbox);  <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme.
           k = 16;
    while (k--) buf_shar[index_buf+k] = Coef(buf_shar[index_buf+k]);   
//////////////////////////////////////////////////////////////////////////////////

	
        aes_shiftRows(buf_shar,g,tx,bx,rounds); 			
        aes_mixColumns(buf_shar,g,tx,bx,rounds);


//    for(k=0;k<16;k++) buf_shar[index_buf+k] = (uint8_t) tx;
////        if( i & 1 ) aes_addRoundKey(buf, &key_shar[index_key+16],g,tx,bx);	

        if( i & 1 ){
	register uint8_t t = 16;
         while (t--) buf_shar[index_buf+t] ^= key_shar[index_key+16+t];
                   }

        else {
		
//	  aes_expandEncKey1(key,sbox,&rcon); <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme.

        rc=&rcon;

    	key_shar[index_key+0] ^= Coef(key_shar[index_key+29]) ^ (*rc);
    	key_shar[index_key+1] ^= Coef(key_shar[index_key+30]);
    	key_shar[index_key+2] ^= Coef(key_shar[index_key+31]);
    	key_shar[index_key+3] ^= Coef(key_shar[index_key+28]);
        
    	*rc =(((*rc)<<1) ^ ((((*rc)>>7) & 1) * 0x1b));
	rcon=*rc;
 

    	for(k = 4; k < 16; k += 4)  {
	key_shar[index_key+k] ^= key_shar[index_key+(k-4)];   
	key_shar[index_key+(k+1)] ^= key_shar[index_key+(k-3)];
    	key_shar[index_key+(k+2)] ^= key_shar[index_key+(k-2)];
	key_shar[index_key+(k+3)] ^= key_shar[index_key+(k-1)];
				  }
				      
    	key_shar[index_key+16] ^= Coef(key_shar[index_key+12]);
    	key_shar[index_key+17] ^= Coef(key_shar[index_key+13]);
    	key_shar[index_key+18] ^= Coef(key_shar[index_key+14]);
    	key_shar[index_key+19] ^= Coef(key_shar[index_key+15]);

    	for(k = 20; k < 32; k += 4) {
	key_shar[index_key+k] ^= key_shar[index_key+(k-4)];
        key_shar[index_key+(k+1)] ^= key_shar[index_key+(k-3)];
    	key_shar[index_key+(k+2)] ^= key_shar[index_key+(k-2)];
        key_shar[index_key+(k+3)] ^= key_shar[index_key+(k-1)];
	                              }
				      
				      
//////////////////////////////////////////////////////////////////////////////////

	  aes_addRoundKey(buf_shar, key_shar,g,tx,bx,rounds);
	  
	      }
			
    }
    
__syncthreads();
     
//    aes_subBytes(buf,sbox);      <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme.
    k = 16;
    while (k--) buf_shar[index_buf+k] = Coef(buf_shar[index_buf+k]);   
//////////////////////////////////////////////////////////////////////////////////

    
    aes_shiftRows(buf_shar,g,tx,bx,rounds);  
     
//    aes_expandEncKey1(key,sbox,&rcon);      <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme. 

        rc=&rcon;

    	key_shar[index_key+0] ^= Coef(key_shar[index_key+29]) ^ (*rc);
    	key_shar[index_key+1] ^= Coef(key_shar[index_key+30]);
    	key_shar[index_key+2] ^= Coef(key_shar[index_key+31]);
    	key_shar[index_key+3] ^= Coef(key_shar[index_key+28]);
    
    	*rc =(((*rc)<<1) ^ ((((*rc)>>7) & 1) * 0x1b));
	rcon=*rc;
 
    	for(k = 4; k < 16; k += 4){  
	key_shar[index_key+k] ^= key_shar[index_key+(k-4)];
	key_shar[index_key+(k+1)] ^= key_shar[index_key+(k-3)];
        key_shar[index_key+(k+2)] ^= key_shar[index_key+(k-2)]; 
        key_shar[index_key+(k+3)] ^= key_shar[index_key+(k-1)];
	                          }
    	key_shar[index_key+16] ^= Coef(key_shar[index_key+12]);
    	key_shar[index_key+17] ^= Coef(key_shar[index_key+13]);
    	key_shar[index_key+18] ^= Coef(key_shar[index_key+14]);
    	key_shar[index_key+19] ^= Coef(key_shar[index_key+15]);

    	for(k = 20; k < 32; k += 4){
	key_shar[index_key+k] ^= key_shar[index_key+(k-4)];   
	key_shar[index_key+(k+1)] ^= key_shar[index_key+(k-3)];
    	key_shar[index_key+(k+2)] ^= key_shar[index_key+(k-2)];
        key_shar[index_key+(k+3)] ^= key_shar[index_key+(k-1)];
	                           }
//////////////////////////////////////////////////////////////////////////////////
    
    aes_addRoundKey(buf_shar,key_shar,g,tx,bx,rounds);         
    aes256_done(key_shar,enckey_shar,deckey_shar,g,tx,bx);    
    

__syncthreads();

   
     } /* end 32 cycles for the 512 chunk increments of 16*/

for(int tt=0;tt<512;tt++){   
buf[(rounds*SM_BLOCKS*THREADS)+(bx*THREADS*512)+(tx*512)+tt]=buf_shar[tt];   
                         }



__syncthreads();

   
   
} 



/* -------------------------------------------------------------------------- */

__global__ void aes256_dec_kernel(uint8_t *sbox, uint8_t *sboxinv, uint8_t *buf, uint8_t *key, uint8_t *enckey, uint8_t *deckey, uint8_t *local_key, int rounds)
{
    uint8_t m, rcon2;
    int l,n;
    int g,i,tx,bx; 
    register int index_buf, index_key;


	
    bx = blockIdx.x;
    tx = threadIdx.x;

	__shared__ uint8_t coef[256];
	
	for(int step22=0;step22<256;++step22){
            Coef(step22)=sbox[step22];
                                             }					
 
 
	__shared__ uint8_t coefinv[256];
	
	for(int step33=0;step33<256;++step33){
            Coefinv(step33)=sboxinv[step33];
                                             }					
 


    register uint8_t buf_shar[512];

    for(int stepk=0;stepk<512;++stepk){
    	buf_shar[stepk]=buf[(rounds*SM_BLOCKS*THREADS)+(bx*THREADS*512)+(tx*512)+stepk];
    				}
 
 
    register uint8_t key_shar[1024];
    
    for(int stepl=0;stepl<1024;++stepl){
    	key_shar[stepl]=key[(bx*THREADS*1024)+(tx*1024)+stepl];
    					      }
 
  
    register uint8_t enckey_shar[1024];
    
    for(int stepm=0;stepm<1024;++stepm){
      enckey_shar[stepm]=enckey[(bx*THREADS*1024)+(tx*1024)+stepm];
					    }


    register uint8_t deckey_shar[1024];
    
    for(int stepn=0;stepn<1024;++stepn){
    	deckey_shar[stepn]=deckey[(bx*THREADS*1024)+(tx*1024)+stepn];
    					      }


__syncthreads();

 
    uint8_t *rc;

    for(g = 0; g <32; g++){

    index_buf=(g*16);
    index_key=(g*16);

			
    uint8_t  rcon = 1;
    
//    aes256_init2(sbox, key, enckey, deckey, local_key);      <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme. 


    for (l = 0; l < 32; l++) {  
 			   enckey_shar[index_key+l] = local_key[l];
			   deckey_shar[index_key+l] = local_key[l];
			       }
	
//////////////////////////////////////////////////////////////////////////////////
	
	
				      
    for (l = 8;--l;) {
//    aes_expandEncKey2(sbox, deckey, &rcon);      <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme. 

    rc=&rcon;

    deckey_shar[index_key+0] ^= Coef(deckey_shar[index_key+29]) ^ (*rc);
    deckey_shar[index_key+1] ^= Coef(deckey_shar[index_key+30]);
    deckey_shar[index_key+2] ^= Coef(deckey_shar[index_key+31]);
    deckey_shar[index_key+3] ^= Coef(deckey_shar[index_key+28]);
//    *rc = F( *rc);

    *rc =(((*rc)<<1) ^ ((((*rc)>>7) & 1) * 0x1b));

    rcon=*rc;


    for(m = 4; m < 16; m += 4){  	      
    deckey_shar[index_key+m] ^= deckey_shar[index_key+(m-4)];
    deckey_shar[index_key+(m+1)] ^= deckey_shar[index_key+(m-3)];
    deckey_shar[index_key+(m+2)] ^= deckey_shar[index_key+(m-2)]; 
    deckey_shar[index_key+(m+3)] ^= deckey_shar[index_key+(m-1)];
	                       }
			       
    deckey_shar[index_key+16] ^= Coef(deckey_shar[index_key+12]);
    deckey_shar[index_key+17] ^= Coef(deckey_shar[index_key+13]);
    deckey_shar[index_key+18] ^= Coef(deckey_shar[index_key+14]);
    deckey_shar[index_key+19] ^= Coef(deckey_shar[index_key+15]);

    for(m = 20; m < 32; m += 4){
    deckey_shar[index_key+m] ^= deckey_shar[index_key+(m-4)];
    deckey_shar[index_key+(m+1)] ^= deckey_shar[index_key+(m-3)];   
    deckey_shar[index_key+(m+2)] ^= deckey_shar[index_key+(m-2)]; 
    deckey_shar[index_key+(m+3)] ^= deckey_shar[index_key+(m-1)];
	                       }
    
    
                    }
//////////////////////////////////////////////////////////////////////////////////


    aes_addRoundKey_cpy2(buf_shar,key_shar,deckey_shar,g,tx,bx,rounds);
    aes_shiftRows_inv(buf_shar,g,tx,bx,rounds);
    
    
//    aes_subBytes_inv(buf_shar,sboxinv);      <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme. 
//    register uint8_t i = 16;

    n = 16;
    while (n--) buf_shar[index_buf+n] = Coefinv(buf_shar[index_buf+n]);

//////////////////////////////////////////////////////////////////////////////////

    for (i = 14, rcon2 = 0x80; --i;)
    {
        if( ( i & 1 ) )           
        {

//            aes_expandDecKey(key,sbox,&rcon2);      <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme. 

    uint8_t p;
    rc=&rcon2;

    for(p = 28; p > 16; p -= 4){
     key_shar[index_key+(p+0)] ^= key_shar[index_key+(p-4)];
     key_shar[index_key+(p+1)] ^= key_shar[index_key+(p-3)]; 
     key_shar[index_key+(p+2)] ^= key_shar[index_key+(p-2)];
     key_shar[index_key+(p+3)] ^= key_shar[index_key+(p-1)];
                               }
			       
    key_shar[index_key+16] ^= Coef(key_shar[index_key+12]);
    key_shar[index_key+17] ^= Coef(key_shar[index_key+13]);
    key_shar[index_key+18] ^= Coef(key_shar[index_key+14]);
    key_shar[index_key+19] ^= Coef(key_shar[index_key+15]);

    for(p = 12; p > 0; p -= 4){  
    key_shar[index_key+(p+0)] ^= key_shar[index_key+(p-4)]; 
    key_shar[index_key+(p+1)] ^= key_shar[index_key+(p-3)];
    key_shar[index_key+(p+2)] ^= key_shar[index_key+(p-2)]; 
    key_shar[index_key+(p+3)] ^= key_shar[index_key+(p-1)];
                              }
    *rc =(((*rc) >> 1) ^ (((*rc) & 1) ? 0x8d : 0));

    rcon2=*rc;
    
    key_shar[index_key+0] ^= Coef(key_shar[index_key+29]) ^ (*rc);
    key_shar[index_key+1] ^= Coef(key_shar[index_key+30]);
    key_shar[index_key+2] ^= Coef(key_shar[index_key+31]);
    key_shar[index_key+3] ^= Coef(key_shar[index_key+28]);
	    	    	    
//////////////////////////////////////////////////////////////////////////////////	    	    
	    
//            aes_addRoundKey(buf, &key_shar[index_key+16],g,tx,bx);
	    

//        if( i & 1 ){
	register uint8_t t = 16;
         while (t--) buf_shar[index_buf+t] ^= key_shar[index_key+16+t];
//                   }
	    
	    
	    
	    
        }

        else aes_addRoundKey(buf_shar,key_shar,g,tx,bx,rounds);
	
        aes_mixColumns_inv(buf_shar,g,tx,bx,rounds);
        aes_shiftRows_inv(buf_shar,g,tx,bx,rounds);
			
//        aes_subBytes_inv(buf,sboxinv);      <- this function will be included here
//        in its totallity in order to take advantage of the shared memory scheme. 

    n = 16;
    while (n--) buf_shar[index_buf+n] = Coefinv(buf_shar[index_buf+n]);

//////////////////////////////////////////////////////////////////////////////////
	
	
    }


    aes_addRoundKey(buf_shar,key_shar,g,tx,bx,rounds); 
    aes256_done(key_shar,enckey_shar,deckey_shar,g,tx,bx);    


__syncthreads();

     } /* end g 32 cycles for the 512 chunk increments of 16*/
     

__syncthreads();
     
    
for(int tt=0;tt<512;tt++){   
buf[(rounds*SM_BLOCKS*THREADS)+(bx*THREADS*512)+(tx*512)+tt]=buf_shar[tt];   
                      }
     
__syncthreads();

    
} /* aes256_decrypt */




void process_chunk(int val_enc_dec, uint8_t *key_local, int num_blocks, int num_threads, int number_rounds)
{

//uint8_t buf_local[128000000]; // 512-bytes length of chunk times 1024 possible processors.
//uint8_t key_in[1048576];   // 32-bytes length key times 1024 possible processors.
//uint8_t enckey_in[1048576];  // 32-bytes length key times 1024 possible processors.
//uint8_t deckey_in[1048576];  // 32-bytes length key times 1024 possible processors.


int r;
int number_coeff;
int number_key_bytes; //32 key-bytes 32 key-chars 256-bits wide key

uint8_t *sbox_d;
uint8_t *sboxinv_d;
uint8_t *buffer_d;
uint8_t *key_local_d;
uint8_t *key_d;
uint8_t *enckey_d;
uint8_t *deckey_d;



number_coeff=256;
number_key_bytes=32; //32 key-bytes 256-bits wide key


/* Allocate sbox_d array on device */
cudaMalloc ((void **) &sbox_d, sizeof(uint8_t)*number_coeff);

/* Copy array from host memory to device memory */
cudaMemcpy(sbox_d,sbox,sizeof(uint8_t)*number_coeff,cudaMemcpyHostToDevice);


/* Allocate sboxinv_d array on device */
cudaMalloc ((void **) &sboxinv_d, sizeof(uint8_t)*number_coeff);

/* Copy array from host memory to device memory */
cudaMemcpy(sboxinv_d,sboxinv,sizeof(uint8_t)*number_coeff,cudaMemcpyHostToDevice);


int processors;

processors=SM_BLOCKS*THREADS;
		 
/* Allocate key_d array on device */
cudaMalloc ((void **) &key_local_d, sizeof(uint8_t)*number_key_bytes);

/* Copy array from host memory to device memory */
cudaMemcpy(key_local_d,key_local,sizeof(uint8_t)*number_key_bytes,cudaMemcpyHostToDevice);


/* Allocate key_d array on device */
cudaMalloc ((void **) &key_d, sizeof(uint8_t)*processors*number_key_bytes*number_key_bytes);

/* Copy array from host memory to device memory */
//cudaMemcpy(key_d,key_in,sizeof(uint8_t)*processors*number_key_bytes*number_key_bytes,cudaMemcpyHostToDevice);


/* Allocate enckey_d array on device */
cudaMalloc ((void **) &enckey_d, sizeof(uint8_t)*processors*number_key_bytes*number_key_bytes);

/* Copy array from host memory to device memory */
//cudaMemcpy(enckey_d,enckey_in,sizeof(uint8_t)*processors*number_key_bytes*number_key_bytes,cudaMemcpyHostToDevice);

/* Allocate deckey_d array on device */
cudaMalloc ((void **) &deckey_d, sizeof(uint8_t)*processors*number_key_bytes*number_key_bytes);


/* Copy array from host memory to device memory */
//cudaMemcpy(deckey_d,deckey_in,sizeof(uint8_t)*processors*number_key_bytes*number_key_bytes,cudaMemcpyHostToDevice);


/* Allocate buff_d array on device */
cudaMalloc ((void **) &buffer_d,sizeof(uint8_t)*393216*512);

/* Copy array from host memory to device memory */
cudaMemcpy(buffer_d,postal,sizeof(uint8_t)*393216*512,cudaMemcpyHostToDevice);

/*number of SM_BLOCKS*THREADS rounds) */
for(r=0;r<(number_rounds+1);r++){

if(val_enc_dec==0) aes256_enc_kernel<<<SM_BLOCKS,THREADS>>>(sbox_d,sboxinv_d,buffer_d,key_d,enckey_d,deckey_d,key_local_d,r);
if(val_enc_dec==1) aes256_dec_kernel<<<SM_BLOCKS,THREADS>>>(sbox_d,sboxinv_d,buffer_d,key_d,enckey_d,deckey_d,key_local_d,r);

                                         }

cudaMemcpy(postal,buffer_d,sizeof(uint8_t)*processors*512,cudaMemcpyDeviceToHost);


cudaFree(sbox_d);    
cudaFree(sboxinv_d);
cudaFree(buffer_d);    
cudaFree(key_local_d);
cudaFree(key_d);
cudaFree(enckey_d);
cudaFree(deckey_d);
  
} 


int main(int argc, char *argv[]){
 
uint8_t key_local[32];
    
int val_enc_dec,i,permacount1,limit,valfloor;
int total_data_processed,permacount_processor1;
int num_blocks;
int num_threads;
char string1[500];
char string2[500];
char string3[500];

char infile_str[500];
char outfile_str[500];
char keyfile_str[500];
char encdec[80];
  
  
if(argc == 1){
printf("\n Usage Example:\n");

printf("To encode:\n");
printf("aes256_no_pointer input_file output_file  key_file enc\n");
printf("\n");
printf("To decode:\n");
printf("aes256_no_pointer input_file output_file  key_file dec\n");
printf("\n");

printf("Were key_file: Is a file containing 32 character's. This is: 8-bit or 2-hex (per character).\n");
printf("That represents the 256 bits for the key.\n");
printf("for example:\n");
printf("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f\n");
exit(0);
}



strncpy(string1, argv[1], 180);
sscanf(string1, "%s", &infile_str);
//printf("ifile_str %s\n",infile_str);

strncpy(string2, argv[2], 180);
sscanf(string2, "%s", &outfile_str);
//printf("outfile_str %s\n",outfile_str);

strncpy(string3, argv[3], 180);
sscanf(string3, "%s", &keyfile_str);
//printf("keyfile_str %s\n",keyfile_str);

strncpy(string3, argv[4], 180);
sscanf(string3, "%s", &encdec);
//printf("encdec %s\n",encdec);

val_enc_dec=0;
if(strcmp(encdec,"enc")==0) val_enc_dec=0;
if(strcmp(encdec,"dec")==0) val_enc_dec=1;
   
   char caracter;
   int count1,count3;
   uint8_t string_hex;
   FILE *inputfile;
   FILE *outputfile;
   FILE *keyfile;


   keyfile=fopen(keyfile_str,"rb");         
      
   for (i = 0; i < sizeof(key_local);i++){
	 fscanf(keyfile,"%x",&string_hex);
          key_local[i] = string_hex;
                                          }
  
    fclose(keyfile);   
    
//Count the characters in the input file
  
    int             countchar = 0;  /* number of characters seen */
    FILE           *in_file;    /* input file */

    /* character or EOF flag from input */
    int             ch;

    in_file = fopen(infile_str, "r");
    if (in_file == NULL) {
        printf("Cannot open %s\n",infile_str);
        exit(8);
    }

    while (1) {
        ch = fgetc(in_file);
        if (ch == EOF)
            break;
        ++countchar;
    }
//    printf("Number of characters in %s is %d\n",
//                  infile_str, countchar);

    fclose(in_file);
    
 //end counting characters in input file
     
   inputfile=fopen(infile_str,"rb");
   outputfile=fopen(outfile_str,"wb");

   total_data_processed=0;   

   doitagain:                     /* goto Start Cycle  */


int processors, processor_count1, number_rounds;

processors=393216;  //virtual number


/**********************************************************************************/
/*This part READ a ``postal-card'' of 512 bytes of information from inputfile.*/


   count1=0;            /*start counter*/
   processor_count1=0;  /*start counter*/

   permacount1=0;
   permacount_processor1=0;
   number_rounds=0;
      
   while(feof(inputfile)==0){
   caracter=fgetc(inputfile);
   postal[(processor_count1*512)+count1]=(uint8_t) caracter;
   count1=count1+1;         
   permacount1=count1;     
   permacount_processor1=processor_count1;         
   if(count1==512) processor_count1=processor_count1+1;   
   if((count1==512) & (processor_count1==processors)) break; 
   if((count1==512) & !(processor_count1==processors)) count1=0;   
   
                            }
			 


num_blocks=floor(permacount_processor1/THREADS);
num_threads=permacount_processor1-(num_blocks*THREADS);


/*number of rounds of 192 processors*/ 
number_rounds=floor(permacount_processor1/(SM_BLOCKS*THREADS));

valfloor=floor(countchar/512)*512;


if(((countchar-valfloor)==511) & (((permacount_processor1+1)*512)>=valfloor) & (val_enc_dec==0)) {
                                   postal[((permacount_processor1)*512)+511]= (uint8_t) 170;
				  count1=512;
				  processor_count1=processor_count1+1;
	     	                                                   }

		
			 
/*padding for encoding, input data always finish with a 512 multiple*/	
/*fill the void for the 512 set*/			 
if(count1!=512)	{
for(count3=0;count3<(512-permacount1);count3++){  
   caracter=(uint8_t) (permacount1);                
   if(permacount1>256) caracter= 0xff;    
postal[(processor_count1*512)+count1]=caracter;   
   count1=count1+1; 
               
                                               }
		       					       
if (postal[(processor_count1*512)+511]==0xff){ 	
     postal[(processor_count1*512)+510]=permacount1-256; 	
		                             }	
                }		 
			
			

/**********************************************************************************/
/*PROCESS AES256 512-bytes of chunk of data.*/


process_chunk(val_enc_dec,key_local,num_blocks,num_threads,number_rounds);



/**********************************************************************************/


/*This part WRITE a ``postal-card'' of 512 bytes of information from inputfile.*/


/* write's complete 512-byte's of encoded data.*/
if(val_enc_dec==0){ 
    if((feof(inputfile)==0) & ((permacount_processor1)==(processors-1))){  
//    printf("encdec 3\n");
    for(count3=0;count3<(permacount_processor1+1)*512;count3++){              
   caracter=(uint8_t) postal[count3];          
    fputc(caracter, outputfile);
                                      }
                           }
                  }



//printf("encdec 3\n");	 

/* write's reminder byte's of encoded data.*/     
if(val_enc_dec==0){       
   if (((feof(inputfile)!=0) & ((permacount_processor1)<=(processors-1))) | (((countchar-valfloor)==511) & (total_data_processed>=valfloor))){
   
   for(count3=0; count3<(((permacount_processor1)*512)+count1); count3++){
                   caracter= postal[count3];
                    fputc(caracter,outputfile);
                                                                          }		
                          }
                  }


/****************************************************************************/

/* write's complete 512-byte's of decoded data.*/




if(val_enc_dec==1){ 
    if((feof(inputfile)==0) & ((permacount_processor1)==(processors-1))){  
    for(count3=0;count3<(permacount_processor1+1)*512;count3++){	      
   caracter=(uint8_t) postal[count3];	       
    fputc(caracter, outputfile);
				                               }
			                                                }
			   
		  }


if(val_enc_dec==1){   

if ((feof(inputfile)!=0) & ((permacount_processor1)<=(processors-1))){
   
   
limit=((permacount_processor1-1)*512)+(int) postal[((permacount_processor1-1)*512)+511];		 
     
    
if (postal[((permacount_processor1-1)*512)+511]==0xff){ 
     limit=((permacount_processor1-1)*512)+((int) postal[((permacount_processor1-1)*512)+510])+256;   
		                                      }
		      
if(postal[((permacount_processor1-1)*512)+511]==0xaa){
                     limit=((permacount_processor1-1)*512)+512;
                                                     }



   for(count3=0; count3<(limit-1); count3++){
                   caracter=(uint8_t) postal[count3];
                    fputc(caracter,outputfile);
                                            }
                                                                      }
                   }


total_data_processed=total_data_processed+((permacount_processor1+1)*512);


    if((feof(inputfile)==0) ) goto doitagain;  /* re-Start Cycle  */
    
    fclose(inputfile);
    fclose(outputfile);

		   
}   /* main */                                                    
                        

