
#define TEST_NAME "vrf_12"
#include "cmptest.h"

typedef struct TestData_ {
    const char seed[2 * crypto_vrf_ietfdraft12_SEEDBYTES + 1];
    const char pk[2 * crypto_vrf_ietfdraft12_PUBLICKEYBYTES + 1];
    const char proof[2 * crypto_vrf_ietfdraft12_PROOFBYTES + 1];
    const char output[2 * crypto_vrf_ietfdraft12_OUTPUTBYTES + 1];
} TestData;
#ifdef TRYANDINC
/*
 * Test data taken from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09#appendix-A.3
 * Note, however, that the proof `pi` is not as specified in the spec because instead of including
 * (Gamma || c || s) in the proof string, we include (Gamma || U || V || s). The values of U and V
 * are taken from the test vectors in the spec.
 */
static const TestData test_data[] = {
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f5e8bd1839b414219e8626d393787a192241fc442e6569e96c462f62b8079b9ed83ff2ee21c90c7c398802fdeebea4001",
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593f7eaf3eb2f1a968cba3f6e23b386aeeaab7b1ea44a256e811892e13eeae7c9f6ea8992557453eac11c4d5476b1f35a08",
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        },
        {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80e29dc513c01c3a980e0e545bcd848222d08a6c3e3665ff5a4cab13a643bef812e284c6b2ee063a2cb4f456794723ad0a",
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        }
};
#else
/*
 * Test data taken from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09#appendix-A.4
 */
static const TestData test_data[] = {
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
            "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
            "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
        },
        {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
            "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
        }
};
#endif

static const unsigned char messages[3][2] = {{0x00}, {0x72}, {0xaf, 0x82}};

static inline void printhex(const char *label, const unsigned char *c, size_t len){
    size_t i;
    printf("%s", label);
    for (i = 0; i < len; i++){
        printf("%02x", c[i]);
    }
    printf("\n");
}

int main(void)
{
    unsigned char *seed, *expected_pk, *expected_proof, *expected_output;
    seed            = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft12_SEEDBYTES);
    expected_pk     = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft12_PUBLICKEYBYTES);
    expected_proof  = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft12_PROOFBYTES);
    expected_output = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft12_OUTPUTBYTES);

    unsigned char sk[crypto_vrf_ietfdraft12_SECRETKEYBYTES];
    unsigned char pk[crypto_vrf_ietfdraft12_PUBLICKEYBYTES];
    unsigned char proof[crypto_vrf_ietfdraft12_PROOFBYTES];
    unsigned char output[crypto_vrf_ietfdraft12_OUTPUTBYTES];

    unsigned int i;
    assert(crypto_vrf_ietfdraft12_SECRETKEYBYTES == 64);
    assert(crypto_vrf_ietfdraft12_PUBLICKEYBYTES == 32);
    assert(crypto_vrf_ietfdraft12_SEEDBYTES == 32);
    assert(crypto_vrf_ietfdraft12_PROOFBYTES == 80);
    assert(crypto_vrf_ietfdraft12_OUTPUTBYTES == 64);

    for (i = 0U; i < (sizeof test_data) / (sizeof test_data[0]); i++) {
        sodium_hex2bin(seed, crypto_vrf_ietfdraft12_SEEDBYTES,
                       test_data[i].seed, (size_t) -1U, NULL, NULL, NULL);
        sodium_hex2bin(expected_pk, crypto_vrf_ietfdraft12_PUBLICKEYBYTES,
                       test_data[i].pk, (size_t) -1U, NULL, NULL, NULL);
        sodium_hex2bin(expected_proof, crypto_vrf_ietfdraft12_PROOFBYTES,
                       test_data[i].proof, (size_t) -1U, NULL, NULL, NULL);
        sodium_hex2bin(expected_output, crypto_vrf_ietfdraft12_OUTPUTBYTES,
                       test_data[i].output, (size_t) -1U, NULL, NULL, NULL);

        crypto_vrf_ietfdraft12_keypair_from_seed(pk, sk, seed);
        if (memcmp(pk, expected_pk, crypto_vrf_ietfdraft12_PUBLICKEYBYTES) != 0){
            printf("keypair_from_seed produced wrong pk: [%u]\n", i);
            printhex("\tWanted: ", expected_pk, crypto_vrf_ietfdraft12_PUBLICKEYBYTES);
            printhex("\tGot:    ", pk, crypto_vrf_ietfdraft12_PUBLICKEYBYTES);
        }
        if (!crypto_vrf_ietfdraft12_is_valid_key(pk)) {
            printf("crypto_vrf_is_valid_key() error: [%u]\n", i);
        }
        if (crypto_vrf_ietfdraft12_prove(proof, sk, messages[i], i) != 0){
            printf("crypto_vrf_prove() error: [%u]\n", i);
        }
        if (memcmp(expected_proof, proof, crypto_vrf_ietfdraft12_PROOFBYTES) != 0){
            printf("proof error: [%u]\n", i);
            printhex("\tWanted: ", expected_proof, crypto_vrf_ietfdraft12_PROOFBYTES);
            printhex("\tGot:    ", proof, crypto_vrf_ietfdraft12_PROOFBYTES);
        }
        if (crypto_vrf_ietfdraft12_verify(output, expected_pk, proof, messages[i], i) != 0){
            printf("verify error: [%u]\n", i);
        }
        if (memcmp(output, expected_output, crypto_vrf_ietfdraft12_OUTPUTBYTES) != 0){
            printf("output wrong: [%u]\n", i);
            printhex("\tWanted: ", expected_output, crypto_vrf_ietfdraft12_OUTPUTBYTES);
            printhex("\tGot:    ", output, crypto_vrf_ietfdraft12_OUTPUTBYTES);
        }

        proof[0] ^= 0x01;
        if (crypto_vrf_ietfdraft12_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad gamma: [%u]\n", i);
        }
        proof[0] ^= 0x01;
        proof[32] ^= 0x01;
        if (crypto_vrf_ietfdraft12_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad c value: [%u]\n", i);
        }
        proof[32] ^= 0x01;
        proof[48] ^= 0x01;
        if (crypto_vrf_ietfdraft12_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad s value: [%u]\n", i);
        }
        proof[48] ^= 0x01;
        proof[79] ^= 0x80;
        if (crypto_vrf_ietfdraft12_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad s value (high-order-bit flipped): [%u]\n", i);
        }
        proof[79] ^= 0x80;

        if (i > 0) {
            if (crypto_vrf_ietfdraft12_verify(output, expected_pk, proof, messages[i], i-1) == 0){
                printf("verify succeeded with truncated message: [%u]\n", i);
            }
        }

        if (crypto_vrf_ietfdraft12_proof_to_hash(output, proof) != 0){
            printf("crypto_vrf_proof_to_hash() error: [%u]\n", i);
        }
        if (memcmp(output, expected_output, crypto_vrf_ietfdraft12_OUTPUTBYTES) != 0){
            printf("output wrong: [%u]\n", i);
        }
    }
    printf("%u tests\n", i);
    return 0;
}
