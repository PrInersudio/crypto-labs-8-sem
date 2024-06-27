#include<stdio.h>
#include<stdlib.h>
#include <stdint.h>
#include"hmac.cuh"
//#include"aes.cuh"
#define FILELEN 76
#define FILENAME "task3.txt"
__device__ uint8_t passwordG[] = "Fasgdh346ylbne";
#define LEN_PASSWORD 14
#define LENSALT 4
#define CT_LEN (FILELEN - 12)
#define KEYLENGTH 16

__device__ size_t cuda_strlen(uint8_t* str) {
    size_t i = 0;
    while (str[i] != '\0') ++i;
    return i;
}

#define RotWord(value) ((value << 8) | (value >> 24))

__device__
uint8_t SboxG[] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

__device__
uint8_t InvSboxG[] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };

__device__
uint32_t RconG[] = { 0x00000000, 0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000};

__device__
void InvShiftRow(uint8_t *state) {
    uint8_t temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    temp = state[14];
    state[14] = state[6];
    state[6] = temp;
    temp = state[10];
    state[10] = state[2];
    state[2] = temp;
    temp = state[15];
    state[15] = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = temp;
}

__device__
uint32_t SubWord(uint32_t word, uint8_t* Sbox) {
	uint32_t new_word = 0;
	for (int i = 0; i < 4; ++i)
		((uint8_t*)(&new_word))[i] = Sbox[((uint8_t*)(&word))[i]];
	return new_word;
}

__device__
void key_sheldure(uint8_t* key, uint32_t* w, uint8_t* Sbox, uint32_t* Rcon) {
	uint32_t temp;
	int i = 0;
	while (i < 4) {
		((uint8_t*)(w+i))[0] = key[4*i+3];
		((uint8_t*)(w+i))[1] = key[4*i+2];
		((uint8_t*)(w+i))[2] = key[4*i+1];
		((uint8_t*)(w+i))[3] = key[4*i];
		++i;
	}
	while(i < 44) {
		temp = w[i-1];
		if (i % 4 == 0)
			temp = SubWord(RotWord(temp), Sbox) ^ Rcon[i / 4];
		w[i] = w[i - 4] ^ temp;
		++i;
	}
}

__device__
void getWordByIndex(int64_t index, uint8_t* word, uint8_t* password) {
    int64_t i = 0;
    while (index >= 0) {
        int64_t len = i + 1;
        int64_t total = LEN_PASSWORD;

        for (int64_t j = 1; j < len; j++) {
            total *= LEN_PASSWORD;
        }

        if (index < total) {
            int64_t num = index;
            for (int64_t k = len - 1; k >= 0; k--) {
                word[k] = password[num % LEN_PASSWORD];
                num /= LEN_PASSWORD;
            }
            word[len] = '\0';
            return;
        }

        index -= total;
        i++;
    }

    word[0] = '\0';
}

typedef uint8_t state_t[4][4];

__device__
static uint8_t xtime(uint8_t x) {
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

__device__
static uint8_t Multiply(uint8_t x, uint8_t y) {
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

__device__
void InvSubBytes(uint8_t* word, uint8_t* InvSbox) {
	for (int i = 0; i < 16; ++i) word[i] = InvSbox[word[i]];
}

__device__
void invMixColumns(uint8_t* ct) {
    state_t state;
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            state[i][j] = ct[4*i+j];
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i) {
        a = state[i][0];
        b = state[i][1];
        c = state[i][2];
        d = state[i][3];

        state[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            ct[4*i+j] = state[i][j];
}


// Th

/* __device__ uint8_t invMixColumsTable[] = {0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e};

__device__
uint8_t GMul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) p ^= a;
        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

__device__
void invMixColumns(uint8_t* ct) {
    printf("inv mix col ");
    for(int i = 0; i < 16; ++i) printf("%x ", ct[i]);
    printf("\n");
    uint8_t result[16];
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j) {
            result[i * 4 + j] = 0;
            for (int k = 0; k < 4; ++k)
                result[i * 4 + j] ^= GMul(invMixColumsTable[i * 4 + k], ct[k * 4 + j]);
        }
    printf("result ");
    for(int i = 0; i < 16; ++i) printf("%x ", result[i]);
    printf("\n");
    memcpy(ct, result, 16);
} */

__device__
void AddRoundKey(uint8_t* text, uint8_t* round_key) {
    for (int i = 0; i < 4; ++i) text[i] ^= round_key[3-i];
    for (int i = 0; i < 4; ++i) text[4+i] ^= round_key[7-i];
    for (int i = 0; i < 4; ++i) text[8+i] ^= round_key[11-i];
    for (int i = 0; i < 4; ++i) text[12+i] ^= round_key[15-i];
}

__device__
void aes_decrypt(uint8_t* ct, uint32_t* w, uint8_t* InvSbox) {
    AddRoundKey(ct, (uint8_t*)(w+40));
    for (int round = 9; round >= 1; --round) {
        InvShiftRow(ct);
        InvSubBytes(ct, InvSbox);
        AddRoundKey(ct, (uint8_t*)(w+(4 * round)));
        invMixColumns(ct);
    }
    InvShiftRow(ct);
    InvSubBytes(ct, InvSbox);
    AddRoundKey(ct, (uint8_t*)w);
}
/*
#define F0(m,l,k) (m&l | ~m&k)
#define F1(m,l,k) (m ^ l ^ k)
#define F2(m,l,k) (m&l | m&k | l&k)
#define F3(m,l,k) (m ^ l ^ k)
#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6
#define LEFT_ROTATE_32(x,y) (((x) << (y)) | ((x) >> (32-(y)))) */


/* __device__
void sha1(uint8_t* text, u_int64_t len_text, uint8_t* hash) {
    len_text *= 8;
    int padding = len_text % 512 >= 448 ? 512 - (len_text % 512) + 448 : 448 - (len_text % 512);
    int len_padded_text = (len_text + padding + 64) / 8;
    uint8_t* padded_text = (uint8_t*)malloc(len_padded_text);
    memset(padded_text, 0, len_padded_text);
    memcpy(padded_text, text, len_text % 8 == 0 ? len_text / 8 : len_text / 8 + 1);
    padded_text[len_text / 8] |= padding % 8 > 0 ? 1 << (padding % 8 - 1) : 0x80;
    for (int i = 0; i < 64; ++i) padded_text[len_padded_text - 1 - i] = ((uint8_t*)(&len_text))[i];
    uint32_t A = 0x67452301;
    uint32_t B = 0xEFCDAB89;
    uint32_t C = 0x98BADCFE;
    uint32_t D = 0x10325476;
    uint32_t E = 0xC3D2E1F0;
    for(int num_block = 0; num_block < len_padded_text / 64; ++num_block) {
        uint32_t a = A; uint32_t b = B; uint32_t c = C; uint32_t d = D; uint32_t e = E;
        uint32_t W[80];
        for (int i = 0; i < 16; ++i)
            for (int j = 0; j < 4; ++j)
                ((int8_t*)(W+i))[3-j] = padded_text[num_block * 64 + i * 4 + j];
        for (int i = 16; i < 80; ++i) W[i] = LEFT_ROTATE_32(W[i-3]^W[i-8]^W[i-14]^W[i-16], 1);
        for (int i = 0; i < 20; ++i) {
            uint32_t temp = LEFT_ROTATE_32(a,5) + F0(b,c,d) + e + W[i] + K0;
            e = d;
            d = c;
            c = LEFT_ROTATE_32(b,30);
            b = a;
            a = temp;            
        }
        for (int i = 20; i < 40; ++i) {
            uint32_t temp = LEFT_ROTATE_32(a,5) + F1(b,c,d) + e + W[i] + K1;
            e = d;
            d = c;
            c = LEFT_ROTATE_32(b,30);
            b = a;
            a = temp;            
        }
        for (int i = 40; i < 60; ++i) {
            uint32_t temp = LEFT_ROTATE_32(a,5) + F2(b,c,d) + e + W[i] + K2;
            e = d;
            d = c;
            c = LEFT_ROTATE_32(b,30);
            b = a;
            a = temp;            
        }
        for (int i = 60; i < 80; ++i) {
            uint32_t temp = LEFT_ROTATE_32(a,5) + F3(b,c,d) + e + W[i] + K3;
            e = d;
            d = c;
            c = LEFT_ROTATE_32(b,30);
            b = a;
            a = temp;            
        }
        A += a; B+=b, C+=c, D+=d; E+=e;
    }
    for (int i = 0; i < 4; ++i) hash[i] = ((uint8_t*)(&A))[3-i];
    for (int i = 0; i < 4; ++i) hash[4+i] = ((uint8_t*)(&B))[3-i];
    for (int i = 0; i < 4; ++i) hash[8+i] = ((uint8_t*)(&C))[3-i];
    for (int i = 0; i < 4; ++i) hash[12+i] = ((uint8_t*)(&D))[3-i];
    for (int i = 0; i < 4; ++i) hash[16+i] = ((uint8_t*)(&E))[3-i];
    free(padded_text);
} */

/* __device__
void HMAC_SHA1(uint8_t* text, size_t len_text, uint8_t* key, size_t len_key, uint8_t* result) {
    uint8_t block_sized_key[64];
    memset(block_sized_key, 0, 64);
    if (len_key > 64) {
        sha1(key, len_key, block_sized_key);
    }
    else memcpy(block_sized_key, key, len_key);
    uint8_t o_key_pad[64];
    uint8_t i_key_pad[64];
    for (int i = 0; i < 64; ++i) {
        o_key_pad[i] = block_sized_key[i] ^ 0x5c;
        i_key_pad[i] = block_sized_key[i] ^ 0x36;
    }
    uint8_t* buf = (uint8_t*)malloc(64+len_text);
    memcpy(buf, i_key_pad, 64);
    memcpy(buf+64, text, len_text);
    sha1(buf, 64+len_text, result);
    free(buf);
    uint8_t buf2[84];
    memcpy(buf2, o_key_pad, 64);
    memcpy(buf2 + 64, result, 20);
    sha1(buf2, 84, result);
} */

__device__
void PBKDF2_HMAC_SHA1(uint8_t* passwd, uint8_t* salt, int counter, uint8_t* key) {
    size_t len_digest = 20;
    memset(key, 0, 20);
    uint8_t U[20] = {0};
    size_t len_passwd = cuda_strlen(passwd);
    uint8_t buf[8];
    memcpy(buf, salt, 4);
    buf[7] = (uint8_t)0x01;
    memset(buf + 4, 0, 3);
    //HMAC_SHA1(buf, 8, passwd, len_passwd, U);
    hmac_sha1(passwd, len_passwd, buf, 8, U, &len_digest);
    for(int i = 0; i < 20; ++i) key[i] ^= U[i];
    for (int i = 1; i < counter; ++i) {
        //HMAC_SHA1(U, 20, passwd, len_passwd, U);
        hmac_sha1(passwd,len_passwd,U,20,U,&len_digest);
        for(int i = 0; i < 20; ++i) key[i] ^= U[i];
    }
}

__global__
void decrypt(uint8_t* ct, uint8_t* salt, int counter, int pt_size, int64_t start_index) { 
    __shared__ uint8_t passwordS[LEN_PASSWORD];
    __shared__ uint8_t SboxS[256];
    __shared__ uint8_t InvSboxS[256];
    __shared__ uint32_t RconS[11];

    if (threadIdx.x < LEN_PASSWORD)
        passwordS[threadIdx.x] = passwordG[threadIdx.x];
    if (threadIdx.x < 256) {
        SboxS[threadIdx.x] = SboxG[threadIdx.x];
        InvSboxS[threadIdx.x] = InvSboxG[threadIdx.x];
    }
    if (threadIdx.x < 11)
        RconS[threadIdx.x] = RconG[threadIdx.x]; 

    __syncthreads();

    uint8_t text[CT_LEN];
    memcpy(text, ct, CT_LEN);

    int64_t gid = ((((int64_t)blockIdx.x + ((int64_t)blockIdx.y * (int64_t)gridDim.x) + ((int64_t)blockIdx.z * ((int64_t)gridDim.x * (int64_t)gridDim.y))) * ((int64_t)blockDim.x * (int64_t)blockDim.y * (int64_t)blockDim.z)) + ((int64_t)threadIdx.z * ((int64_t)blockDim.x * (int64_t)blockDim.y)) + ((int64_t)threadIdx.y * (int64_t)blockDim.x) + (int64_t)threadIdx.x);
    int64_t index = gid + start_index;
    
    
    uint8_t key[20];
    uint8_t word[LEN_PASSWORD];
    getWordByIndex(index, word, passwordS);
    PBKDF2_HMAC_SHA1(word,salt,counter, key);
    uint32_t key_sheld[44];
    key_sheldure(key, key_sheld, SboxS, RconS);
    //AES_ctx ctx;
    //AES_init_ctx(&ctx, key, SboxS, RconS);
    for (int i = 0; i < CT_LEN; i += 16)
        aes_decrypt(text + i, key_sheld, InvSboxS);
        //AES_ECB_decrypt(&ctx, text+i, SboxS, InvSboxS);
    int acceptable = 0;
    for (int i = 0; i < pt_size; ++i)
        if ((text[i] == '\n') || (text[i] >= ' ') && (text[i] <= '~'))
            ++acceptable;
    if (acceptable == pt_size) {
        text[pt_size] = (uint8_t)0;
        printf("%s %s\n", word, text);
    }
    if (index % 1475789056 == 0)
        printf("%li\n", index);
}

int main() {
    FILE* fp = fopen(FILENAME, "rb");
    if (fp == NULL) {
        printf("Can't open file\n");
        return -1;
    }
    uint8_t buf[FILELEN];
    for (int i = 0; i < FILELEN; ++i) buf[i] = (uint8_t)getc(fp);
    fclose(fp);
    uint8_t* salt;
    uint8_t* ct;
    cudaMalloc(&salt, 4);
    cudaMalloc(&ct, CT_LEN);
    uint32_t counter;
    uint32_t pt_size;
    for (int i = 0; i < 4; ++i) {
        ((uint8_t*)(&counter))[3-i] = buf[4+i];
        ((uint8_t*)(&pt_size))[3-i] = buf[8+i]; 
    }
    printf("%u %u\n", counter, pt_size);
    cudaMemcpy(salt, buf, 4, cudaMemcpyHostToDevice);
    cudaMemcpy(ct, buf+12, CT_LEN, cudaMemcpyHostToDevice);
    int64_t tries = 854769755812155;
    for (int64_t i = 67886296576; i < tries; i+=((int64_t)1<<30)*(int64_t)256) {
        decrypt<<<(1<<30),256>>>(ct, salt, counter, pt_size, i);
        cudaDeviceSynchronize();
        printf("end of set of threads %li\n", i);
    }
    /* decrypt<<<1,1>>>(ct, salt, counter, pt_size, 0);
    cudaDeviceSynchronize(); */
}