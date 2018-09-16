/* Proof of Concept of the Attack on OPP

    :copyright: (c) 2018 by Miloslav Homer
    :license: Creative Commons CC0 1.0
*/

/*
    MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :license: Creative Commons CC0 1.0
*/
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

/* constants holding number of bytes for two blocks and a byte and one block and a byte */
#define TWO_AND_BYTE 257 
#define ONE_AND_BYTE 129

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

int attackPoC(
		const unsigned char *h, size_t hlen, 
		const unsigned char *n, 
		const unsigned char *k)
{
    unsigned i;
	int success = -1;

	/* initialize variables holding plaintext and forgery */
    unsigned char m[TWO_AND_BYTE];
    unsigned char c[TWO_AND_BYTE + 32];
	unsigned char f[ONE_AND_BYTE + 32];
    size_t mlen;
    size_t clen;
	size_t flen;
    memset(m, 0, sizeof m);
	memset(f, 0, sizeof f);
	clen = 0;
    mlen = hlen = TWO_AND_BYTE;
	flen = ONE_AND_BYTE+32;

	/* make query */
    crypto_aead_encrypt(c, &clen, h, hlen, m, mlen, n, k);

	/* null plaintext for decryption purposes */
    memset(m, 0, sizeof m);
    mlen = 0;

	/* make forgery */
	memcpy(f, c, ONE_AND_BYTE);
	memcpy(f+ONE_AND_BYTE, c+TWO_AND_BYTE, 32);

	/* cycle through possible last bytes */
	for (i = 0; i<256; i++) {
		f[ONE_AND_BYTE -1] = (char)i;
		
		/* test forgery */
    	if( 0 == crypto_aead_decrypt(m, &mlen, h, hlen, f, flen, n, k) ) {
			success = i;
			break;
		}
	}
	return success;
}

int main()
{
    int missing_byte;
	/* choose nonce, key, header randomly */
	unsigned i;
    unsigned char h[TWO_AND_BYTE];
    unsigned char k[32];
    unsigned char n[16];
    srand(time(NULL));
    for(i = 0; i < sizeof h; ++i) h[i] = rand() % 256;
    for(i = 0; i < sizeof k; ++i) k[i] = rand() % 256;
    for(i = 0; i < sizeof n; ++i) n[i] = rand() % 256;

	missing_byte = attackPoC(h, sizeof h, n, k);
	if (missing_byte != -1) printf("Got 'em! - byte %02x\n", missing_byte);
	else printf("Invalid forgery :(\n");

	return 0;
}

#undef TWO_AND_BYTE
#undef ONE_AND_BYTE
