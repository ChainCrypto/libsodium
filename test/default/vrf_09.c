
#define TEST_NAME "vrf_09"
#include "cmptest.h"

typedef struct TestData_ {
    const char seed[2 * crypto_vrf_ietfdraft09_SEEDBYTES + 1];
    const char pk[2 * crypto_vrf_ietfdraft09_PUBLICKEYBYTES + 1];
    const char proof[2 * crypto_vrf_ietfdraft09_PROOFBYTES + 1];
    const char output[2 * crypto_vrf_ietfdraft09_OUTPUTBYTES + 1];
} TestData;

/*
 * Test data taken from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09#appendix-A.4
 * Note, however, that the proof `pi` is not as specified in the spec because instead of including
 * (Gamma || c || s) in the proof string, we include (Gamma || U || V || s). The values of U and V
 * are taken from the test vectors in the spec.
 */
static const TestData test_data[] = {
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f762f5c178b68f0cddcc1157918edf45ec334ac8e8286601a3256c3bbf858edd94652eba1c4612e6fce762977a59420b451e12964adbe4fbecd58a7aeff5860afe61b387b76db60b3cbf34bf09109ccb33fab742a8bddc0c8ba3caf5c0b75bb04",
            "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef8ec26e77b8cb3114dd2265fe1564a4efb40d109aa3312536d93dfe3d8d80a061fe799eb5770b4e3a5a27d22518bb631db183c8316bb552155f442c62a47d1c8bda28b5569e74caa418bae7ef521f2ddd35f5727d271ecc70b4a83c1fc8ebc40c",
            "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
        },
        {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdcea012f35433df219a88ab0f9481f4e0065d00422c3285f3d34a8b0202f20bac60fb613986d171b3e98319c7ca4dc44c5dd8314a6e5616c1a4f16ce72bd7a0c25a9ca0418099fbd86a48093e6a8de26307b8d93e02da927e6dd5b73c8f119aee0f",
            "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
        }
};

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
    seed            = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft09_SEEDBYTES);
    expected_pk     = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft09_PUBLICKEYBYTES);
    expected_proof  = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft09_PROOFBYTES);
    expected_output = (unsigned char *) sodium_malloc(crypto_vrf_ietfdraft09_OUTPUTBYTES);

    unsigned char sk[crypto_vrf_ietfdraft09_SECRETKEYBYTES];
    unsigned char pk[crypto_vrf_ietfdraft09_PUBLICKEYBYTES];
    unsigned char proof[crypto_vrf_ietfdraft09_PROOFBYTES];
    unsigned char output[crypto_vrf_ietfdraft09_OUTPUTBYTES];

    unsigned int i;
    assert(crypto_vrf_ietfdraft09_SECRETKEYBYTES == 64);
    assert(crypto_vrf_ietfdraft09_PUBLICKEYBYTES == 32);
    assert(crypto_vrf_ietfdraft09_SEEDBYTES == 32);
    assert(crypto_vrf_ietfdraft09_PROOFBYTES == 128);
    assert(crypto_vrf_ietfdraft09_OUTPUTBYTES == 64);

    for (i = 0U; i < (sizeof test_data) / (sizeof test_data[0]); i++) {
        sodium_hex2bin(seed, crypto_vrf_ietfdraft09_SEEDBYTES,
                       test_data[i].seed, (size_t) -1U, NULL, NULL, NULL);
        sodium_hex2bin(expected_pk, crypto_vrf_ietfdraft09_PUBLICKEYBYTES,
                       test_data[i].pk, (size_t) -1U, NULL, NULL, NULL);
        sodium_hex2bin(expected_proof, crypto_vrf_ietfdraft09_PROOFBYTES,
                       test_data[i].proof, (size_t) -1U, NULL, NULL, NULL);
        sodium_hex2bin(expected_output, crypto_vrf_ietfdraft09_OUTPUTBYTES,
                       test_data[i].output, (size_t) -1U, NULL, NULL, NULL);

        crypto_vrf_ietfdraft09_keypair_from_seed(pk, sk, seed);
        if (memcmp(pk, expected_pk, crypto_vrf_ietfdraft09_PUBLICKEYBYTES) != 0){
            printf("keypair_from_seed produced wrong pk: [%u]\n", i);
            printhex("\tWanted: ", expected_pk, crypto_vrf_ietfdraft09_PUBLICKEYBYTES);
            printhex("\tGot:    ", pk, crypto_vrf_ietfdraft09_PUBLICKEYBYTES);
        }
        if (!crypto_vrf_ietfdraft09_is_valid_key(pk)) {
            printf("crypto_vrf_is_valid_key() error: [%u]\n", i);
        }
        if (crypto_vrf_ietfdraft09_prove(proof, sk, messages[i], i) != 0){
            printf("crypto_vrf_prove() error: [%u]\n", i);
        }
        if (memcmp(expected_proof, proof, crypto_vrf_ietfdraft09_PROOFBYTES) != 0){
            printf("proof error: [%u]\n", i);
            printhex("\tWanted: ", expected_proof, crypto_vrf_ietfdraft09_PROOFBYTES);
            printhex("\tGot:    ", proof, crypto_vrf_ietfdraft09_PROOFBYTES);
        }
        if (crypto_vrf_ietfdraft09_verify(output, expected_pk, proof, messages[i], i) != 0){
            printf("verify error: [%u]\n", i);
        }
        if (memcmp(output, expected_output, crypto_vrf_ietfdraft09_OUTPUTBYTES) != 0){
            printf("output wrong: [%u]\n", i);
            printhex("\tWanted: ", expected_output, crypto_vrf_ietfdraft09_OUTPUTBYTES);
            printhex("\tGot:    ", output, crypto_vrf_ietfdraft09_OUTPUTBYTES);
        }

        proof[0] ^= 0x01;
        if (crypto_vrf_ietfdraft09_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad gamma: [%u]\n", i);
        }
        proof[0] ^= 0x01;
        proof[32] ^= 0x01;
        if (crypto_vrf_ietfdraft09_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad c value: [%u]\n", i);
        }
        proof[32] ^= 0x01;
        proof[48] ^= 0x01;
        if (crypto_vrf_ietfdraft09_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad s value: [%u]\n", i);
        }
        proof[48] ^= 0x01;
        proof[79] ^= 0x80;
        if (crypto_vrf_ietfdraft09_verify(output, expected_pk, proof, messages[i], i) == 0){
            printf("verify succeeded with bad s value (high-order-bit flipped): [%u]\n", i);
        }
        proof[79] ^= 0x80;

        if (i > 0) {
            if (crypto_vrf_ietfdraft09_verify(output, expected_pk, proof, messages[i], i-1) == 0){
                printf("verify succeeded with truncated message: [%u]\n", i);
            }
        }

        if (crypto_vrf_ietfdraft09_proof_to_hash(output, proof) != 0){
            printf("crypto_vrf_proof_to_hash() error: [%u]\n", i);
        }
        if (memcmp(output, expected_output, crypto_vrf_ietfdraft09_OUTPUTBYTES) != 0){
            printf("output wrong: [%u]\n", i);
        }
    }
    printf("%u tests\n", i);
    return 0;
}
