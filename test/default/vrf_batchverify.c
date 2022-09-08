#define TEST_NAME "vrf_batchverify"
#include "cmptest.h"

typedef struct TestData_ {
    const char seed[2 * 32 + 1];
} TestData;
/*
 * Test data taken from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-13#appendix-A.4
 * which contains the seeds. The expected values for the pk, proof and output are in vrf.exp
 */
static const TestData test_data[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"},
};

static const unsigned char messages[3][2] = {{0x00}, {0x72}, {0xaf, 0x82}};
static const unsigned long long msglen[3] = {0, 1, 2};

int main(void)
{
    char output_hex[64 * 2 + 1];
    unsigned char *seed;

    const unsigned char** m = malloc(sizeof(char*) * 3);
    unsigned char** sk = malloc(sizeof(char*) * 3);
    unsigned char** pk = malloc(sizeof(char*) * 3);
    unsigned char** proof = malloc(sizeof(char*) * 3);
    unsigned char** output = malloc(sizeof(char*) * 3);
    unsigned int i;

    seed            = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft13_SEEDBYTES);

    for(i=0;i<3;i++){
        m[i] = malloc(sizeof(char) * msglen[i]);
        sk[i] = malloc(sizeof(char) * 64);
        pk[i] = malloc(sizeof(char) * 32);
        proof[i] = malloc(sizeof(char) * 128);
        output[i] = malloc(sizeof(char) * 64);
    }

    for (i = 0U; i < (sizeof test_data) / (sizeof test_data[0]); i++) {
        sodium_hex2bin(seed, 32,
                       test_data[i].seed, (size_t) -1U, NULL, NULL, NULL);

        crypto_vrf_seed_keypair(pk[i], sk[i], seed);

        if (crypto_vrf_ietfdraft13_prove_batchcompat(proof[i], messages[i], i, sk[i]) != 0){
            printf("crypto_vrf_prove() error: [%u]\n", i);
        }

        if (crypto_vrf_ietfdraft13_verify_batchcompat(output[i], pk[i], proof[i], messages[i], msglen[i]) != 0){
            printf("verify error: [%u]\n", i);
        }

        m[i] = messages[i];
    }

    if (crypto_vrf_ietfdraft13_batch_verify(output, (const unsigned char **) pk, (const unsigned char **) proof, m, msglen, 3) != 0) {
        printf("batch verify failed in the normal ops!\n\n");
        return -1;
    }

    proof[0][0] ^= 0x01;
    if (crypto_vrf_ietfdraft13_batch_verify(output, (const unsigned char **) pk, (const unsigned char **) proof, m, msglen, 3) == 0) {
        printf("verify succeeded with bad gamma: [%u]\n", i);
        return -1;
    }

    proof[0][0] ^= 0x01;
    proof[0][32] ^= 0x01;

    if (crypto_vrf_ietfdraft13_batch_verify(output, (const unsigned char **) pk, (const unsigned char **) proof, m, msglen, 3) == 0) {
        printf("verify succeeded with bad U value: [%u]\n", i);
        return -1;
    }

    proof[0][32] ^= 0x01;
    proof[0][64] ^= 0x01;

    if (crypto_vrf_ietfdraft13_batch_verify(output, (const unsigned char **) pk, (const unsigned char **) proof, m, msglen, 3) == 0) {
        printf("verify succeeded with bad V value: [%u]\n", i);
        return -1;
    }

    proof[0][64] ^= 0x01;
    proof[0][96] ^= 0x01;

    if (crypto_vrf_ietfdraft13_batch_verify(output, (const unsigned char **) pk, (const unsigned char **) proof, m, msglen, 3) == 0) {
        printf("verify succeeded with bad s value: [%u]\n", i);
        return -1;
    }

    proof[0][96] ^= 0x01;
    proof[0][127] ^= 0x80;

    if (crypto_vrf_ietfdraft13_batch_verify(output, (const unsigned char **) pk, (const unsigned char **) proof, m, msglen, 3) == 0) {
        printf("verify succeeded with bad s value (high-order-bit flipped): [%u]\n", i);
        return -1;
    }

    printf("Success verification of all proofs as a batch!\n\n");

    for (i = 0U; i < (sizeof test_data) / (sizeof test_data[0]); i++) {
        printf("%s\n", sodium_bin2hex(output_hex, sizeof output_hex, output[i], 64));
    }
    return 0;
}
