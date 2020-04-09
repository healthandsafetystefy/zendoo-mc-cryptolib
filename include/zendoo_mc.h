#ifndef ZENDOO_MC_INCLUDE_H_
#define ZENDOO_MC_INCLUDE_H_

#include <stdint.h>
#include <stdlib.h>

extern "C" {

//Field related functions

    typedef struct field field_t;

    //Get the byte size of a generic field_element
    size_t zendoo_get_field_size_in_bytes(void);

    //Serialize a field into field_bytes given an opaque pointer to it
    bool zendoo_serialize_field(
        const field_t*  field,
        unsigned char*  field_bytes
    );

    //Get an opaque pointer to a field built from its byte serialization
    field_t* zendoo_deserialize_field(const unsigned char* field_bytes);

    //Free memory from allocated field_t
    void zendoo_field_free(field_t* field);

//Pk related functions

    typedef struct pk pk_t;

    //Get the byte size of pk
    size_t zendoo_get_pk_size_in_bytes(void);

    //Serialize a pk into pk_bytes given an opaque pointer to it
    bool zendoo_serialize_pk(
        const pk_t*    pk,
        unsigned char* pk_bytes
    );

    //Get an opaque pointer to a pk built from its byte serialization
    pk_t* zendoo_deserialize_pk(const unsigned char* pk_bytes);

    //Free memory from allocated pk
    void zendoo_pk_free(pk_t* pk);

//Sk related functions

    typedef struct sk sk_t;

    //Get the byte size of sk
    size_t zendoo_get_sk_size_in_bytes(void);

    //Serialize a sk into sk_bytes given an opaque pointer to it
    bool zendoo_serialize_sk(
        const sk_t*    sk,
        unsigned char* sk_bytes
    );

    //Get an opaque pointer to a sk built from its byte serialization
    sk_t* zendoo_deserialize_sk(const unsigned char* sk_bytes);

    //Free memory from allocated sk
    void zendoo_sk_free(sk_t* sk);


//Keypair related functions

    typedef struct {
        pk_t* pk;
        sk_t* sk;
    } keypair_t ;

    void zendoo_keypair_free(keypair_t keys);

//SNARK related functions

    typedef struct ginger_zk_proof ginger_zk_proof_t;

    //Get the byte size of a generic zk proof
    size_t get_ginger_zk_proof_size(void);

    //Serialize a zk proof into zk_proof_bytes given an opaque pointer to it
    bool serialize_ginger_zk_proof(
        const ginger_zk_proof_t* zk_proof,
        unsigned char*           zk_proof_bytes
    );

    //Get an opaque pointer to a zk_proof built from its byte serialization
    ginger_zk_proof_t* deserialize_ginger_zk_proof(const unsigned char* ginger_zk_proof_bytes);

    bool verify_ginger_zk_proof(
        const uint8_t* vk_path,
        size_t vk_path_len,
        const ginger_zk_proof_t* zkp,
        const field_t** public_inputs,
        size_t public_inputs_len
    );

    void ginger_zk_proof_free(ginger_zk_proof_t* zkp);

//Poseidon hash related functions

    field_t* zendoo_compute_poseidon_hash(
        const field_t** input,
        size_t input_len
    );

//Poseidon-based Merkle Tree related functions

    typedef struct ginger_mt      ginger_mt_t;
    typedef struct ginger_mt_path ginger_mt_path_t;

    ginger_mt_t* ginger_mt_new(
        const field_t** leaves,
        size_t leaves_len
    );

    field_t* ginger_mt_get_root(
        const ginger_mt_t* tree
    );

    ginger_mt_path_t* ginger_mt_get_merkle_path(
        const field_t* leaf,
        size_t leaf_index,
        const ginger_mt_t* tree
    );

    bool ginger_mt_verify_merkle_path(
        const field_t* leaf,
        const field_t* mr,
        const ginger_mt_path_t* path
    );

    void ginger_mt_free(
        ginger_mt_t* tree
    );

    void ginger_mt_path_free(
        ginger_mt_path_t* path
    );

//Schnorr signature related functions

    typedef struct schnorr_sig schnorr_sig_t;

    keypair_t zendoo_schnorr_keygen(void);

    pk_t* zendoo_schnorr_get_pk(const sk_t* sk);

    bool zendoo_schnorr_key_verify(const pk_t* pk);

    schnorr_sig_t* zendoo_schnorr_sign(
        const field_t** message,
        size_t message_len,
        const keypair_t keys
    );

    bool zendoo_schnorr_verify(
        const field_t** message,
        size_t message_len,
        const pk_t* pk,
        const schnorr_sig_t* sig
    );

    //Get the byte size of sign
    size_t zendoo_get_schnorr_sig_size_in_bytes(void);

    //Serialize a schnorr sig into sig_bytes given an opaque pointer to it
    bool zendoo_serialize_schnorr_sig(
        const schnorr_sig_t* sig,
        unsigned char* sig_bytes
    );

    //Get an opaque pointer to a schnorr sig built from its byte serialization
    schnorr_sig_t* zendoo_deserialize_schnorr_sig(const unsigned char* sig_bytes);

    //Free memory from allocated schnorr sig
    void zendoo_schnorr_sig_free(schnorr_sig_t* sig);

//VRF related functions

    typedef struct ecvrf_proof ecvrf_proof_t;

    keypair_t zendoo_ecvrf_keygen(void);

    pk_t* zendoo_ecvrf_get_pk(const sk_t* sk);

    bool zendoo_ecvrf_key_verify(const pk_t* pk);

    ecvrf_proof_t* zendoo_ecvrf_prove(
        const field_t** message,
        size_t message_len,
        const keypair_t keys
    );

    field_t* zendoo_ecvrf_proof_to_hash(
        const field_t** message,
        size_t message_len,
        const pk_t* pk,
        const ecvrf_proof_t* proof
    );

    //Get the byte size of a ecvrf proof
    size_t zendoo_get_ecvrf_proof_size_in_bytes(void);

    //Serialize an ecvrf proof into ecvrf_proof_bytes given an opaque pointer to it
    bool zendoo_serialize_ecvrf_proof(
        const ecvrf_proof_t* ecvrf_proof,
        unsigned char* proof_bytes
    );

    //Get an opaque pointer to an ecvrf_proof built from its byte serialization
    ecvrf_proof_t* zendoo_deserialize_ecvrf_proof(const unsigned char* proof_bytes);

    //Free memory from allocated ecvrf proof
    void zendoo_ecvrf_proof_free(ecvrf_proof_t* proof);

//Naive threshold sig circuit related functions

    ginger_zk_proof_t* zendoo_create_naive_threshold_sig_proof(
        const uint8_t* params_path,
        size_t params_path_len,
        const pk_t** pks,
        size_t pk_num,
        const schnorr_sig_t** sigs,
        size_t sig_num,
        const field_t* threshold,
        const field_t* b,
        const field_t* message,
        const field_t* hash_commitment,
        size_t n
    );

    field_t* zendoo_compute_keys_hash_commitment(
        const pk_t** pks,
        size_t pk_num,
        size_t max_pks
    );

//Test functions

    //Get an opaque pointer to a random field element
    field_t* zendoo_get_random_field(void);

    field_t* zendoo_get_field_from_int(size_t num);

    bool zendoo_field_assert_eq(
        const field_t* field_1,
        const field_t* field_2
    );

    bool zendoo_pk_assert_eq(
        const pk_t* pk_1,
        const pk_t* pk_2
    );

    bool zendoo_sk_assert_eq(
        const sk_t* sk_1,
        const sk_t* sk_2
    );

    bool zendoo_schnorr_sig_assert_eq(
        const schnorr_sig_t* sig_1,
        const schnorr_sig_t* sig_2
    );

    bool zendoo_ecvrf_proof_assert_eq(
        const ecvrf_proof_t* proof_1,
        const ecvrf_proof_t* proof_2
    );

    bool zendoo_generate_random_naive_threshold_sig_parameters(
        const uint8_t* params_path,
        size_t params_path_len,
        const uint8_t* vk_path,
        size_t vk_path_len,
        size_t max_sig
    );
}
#endif // ZENDOO_MC_INCLUDE_H_