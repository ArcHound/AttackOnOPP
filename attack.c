/* proof of concept of the attack on OPP

    :copyright: (c) 2018 by Miloslav Homer
    :license: Creative Commons CC0 1.0
*/
/*
    MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :license: Creative Commons CC0 1.0
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void crypto_aead_encrypt(
        unsigned char *c, size_t *clen,
        const unsigned char *h, size_t hlen,
        const unsigned char *p, size_t plen,
        const unsigned char *nonce,
        const unsigned char *key);

int crypto_aead_decrypt(
        unsigned char *p, size_t *plen,
        const unsigned char *h, size_t hlen,
        const unsigned char *c, size_t clen,
        const unsigned char *nonce,
        const unsigned char *key);

void attackPoC()
{
#define TWO_AND_BYTE 257 
#define ONE_AND_BYTE 129
    unsigned char h[TWO_AND_BYTE];
    unsigned char k[32];
    unsigned char n[16];

    unsigned i;

    unsigned char m[TWO_AND_BYTE];
    unsigned char c[TWO_AND_BYTE + 32];
	unsigned char f[ONE_AND_BYTE + 32];
    size_t mlen;
    size_t clen;
    size_t hlen;
	size_t flen;

    for(i = 0; i < sizeof h; ++i)
        h[i] = 255 & (i*193 + 123);
    for(i = 0; i < sizeof k; ++i)
        k[i] = 255 & (i*191 + 123);
    for(i = 0; i < sizeof n; ++i)
        n[i] = 255 & (i*181 + 123);

    memset(m, 0, sizeof m);
	memset(f, 0, sizeof f);
	clen = 0;
    mlen = hlen = TWO_AND_BYTE;
	flen = ONE_AND_BYTE+32;

	/* make query */
    crypto_aead_encrypt(c, &clen, h, hlen, m, mlen, n, k);

    memset(m, 0, sizeof m);
    mlen = 0;

	/* make forgery */
	memcpy(f, c, ONE_AND_BYTE);
	for (i = 0; i < 32; ++i) {
		f[ONE_AND_BYTE+i] = c[TWO_AND_BYTE+i];
	}

	/* cycle through possible last bytes */
	for (i = 0; i<256; i++) {
		f[ONE_AND_BYTE -1] = (char)i;
		
		/* test forgery */
    	if( 0 == crypto_aead_decrypt(m, &mlen, h, hlen, f, flen, n, k) ) {
			printf("Got em!\n");	
			break;
		}
	}

#undef TWO_AND_BYTE
#undef ONE_AND_BYTE
}

int main()
{
	attackPoC();
	return 0;
}

