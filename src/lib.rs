use algebra::{fields::mnt4753::{Fr, Fq as Fs}, curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{G1Affine, G1Projective},
    ProjectiveCurve,
}, bytes::{FromBytes, ToBytes}, ToBits,
    PrimeField, UniformRand, AffineCurve};

use primitives::{
    crh::{
        FieldBasedHash, MNT4PoseidonHash as FrHash,
        bowe_hopwood::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters},
    },
    merkle_tree::field_based_mht::{
        FieldBasedMerkleHashTree, FieldBasedMerkleTreeConfig, FieldBasedMerkleTreePath
    },
    signature::{
        schnorr::field_based_schnorr::{FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme},
        FieldBasedSignatureScheme,
    },
    vrf::{
        FieldBasedVrf,
        ecvrf::{
            FieldBasedEcVrf, FieldBasedEcVrfProof,
        }
    },
};

use proof_systems::groth16::{
    Proof, prover::create_random_proof,
    verifier::verify_proof, prepare_verifying_key,
};

use demo_circuit::{
    naive_threshold_sig::NaiveTresholdSignature,
    constants::{
        VRFParams, VRFWindow,
    },
};

use rand::rngs::OsRng;
use libc::{
    c_uint, c_uchar
};
use std::{
    path::Path, slice, ffi::OsStr, os::unix::ffi::OsStrExt, fs::File, ptr::null_mut,
    io::{
        Error as IoError, ErrorKind,
    },
};
use lazy_static::*;

pub mod error;
use error::*;

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<G1Projective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<G1Projective>{generators: params.group_hash_generators}
    };
}


#[cfg(test)]
pub mod tests;

// ************CONSTANTS******************

const FR_SIZE: usize = 96;
const FS_SIZE: usize = FR_SIZE; // 96
const G1_SIZE: usize = 193;
const G2_SIZE: usize = 385;

const GROTH_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771
const SIG_SIZE:         usize = 2 * FR_SIZE;            // 192
const VRF_PROOF_SIZE:   usize = G1_SIZE + 2 * FR_SIZE;  // 385

// ************TYPES**********************

pub struct ZendooMcFieldBasedMerkleTreeParams;

impl FieldBasedMerkleTreeConfig for ZendooMcFieldBasedMerkleTreeParams {
    const HEIGHT: usize = 5;
    type H = FrHash;
}

type GingerMerkleTree = FieldBasedMerkleHashTree<ZendooMcFieldBasedMerkleTreeParams>;
type GingerMerkleTreePath = FieldBasedMerkleTreePath<ZendooMcFieldBasedMerkleTreeParams>;
type SchnorrSig = FieldBasedSchnorrSignature<Fr>;
type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<Fr, G1Projective, FrHash>;
type GroupHash = BoweHopwoodPedersenCRH<G1Projective, VRFWindow>;
type EcVrfProof = FieldBasedEcVrfProof<Fr, G1Projective>;
type EcVrfScheme = FieldBasedEcVrf<Fr, G1Projective, FrHash, GroupHash>;
type GingerProof = Proof<PairingCurve>;

// ***********UTILITY FUNCTIONS*************

fn read_raw_pointer<T>(input: *const T, elem_type: &str) -> Option<&T> {
    if input.is_null(){
        set_last_error(Box::new(NullPointerError(format!("Null {}", elem_type))), NULL_PTR_ERROR);
        return None
    }
    Some(unsafe{ &* input })
}

fn read_double_raw_pointer<T: Copy>(input: *const *const T, input_len: usize, elem_type: &str) -> Option<Vec<T>> {

    //Read *const T from *const *const T
    if input.is_null() {
        set_last_error(Box::new(NullPointerError(format!("Ptr to {}s is null", elem_type))), NULL_PTR_ERROR);
        return None
    }
    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read T from *const T
    let mut input = vec![];
    for (i, &ptr) in input_raw.iter().enumerate() {
        if ptr.is_null() {
            set_last_error(Box::new(NullPointerError(format!("{} {} is null", elem_type, i))), NULL_PTR_ERROR);
            return None
        }
        input.push(unsafe{ *ptr });
    }

    Some(input)
}

fn deserialize_from_buffer<T: FromBytes>(buffer: &[u8], buff_size: usize) -> *mut T {
    match T::read(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("should read {} bytes", buff_size));
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut()
        }
    }
}

fn serialize_to_buffer<T: ToBytes>(to_write: *const T, buffer: &mut [u8], buff_size: usize, elem_type: &str) -> bool {
    let to_write = match read_raw_pointer(to_write, elem_type) {
        Some(to_write) => to_write,
        None => return false,
    };

    match to_write.write(buffer){
        Ok(_) => true,
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("should write {} bytes", buff_size));
            set_last_error(Box::new(e), IO_ERROR);
            false
        }
    }
}

fn read_from_file<T: FromBytes>(file_path: *const u8, file_path_len: usize, struct_type: &str) -> Option<T>{
    // Read file path
    let file_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(file_path, file_path_len)
    }));

    // Load struct from file
    let mut fs = match File::open(file_path) {
        Ok(file) => file,
        Err(_) => {
            let e = IoError::new(ErrorKind::NotFound, format!("unable to load {} file", struct_type));
            set_last_error(Box::new(e), IO_ERROR);
            return None
        }
    };

    match T::read(&mut fs) {
        Ok(t) => Some(t),
        Err(_) => {
            let e = IoError::new(ErrorKind::InvalidData, format!("unable to deserialize {} from file", struct_type));
            set_last_error(Box::new(e), IO_ERROR);
            None
        }
    }
}

//***********Field functions****************
#[no_mangle]
pub extern "C" fn zendoo_get_field_size_in_bytes() -> c_uint { FR_SIZE as u32 }

#[no_mangle]
pub extern "C" fn zendoo_serialize_field(
    field_element: *const Fr,
    result:        *mut [c_uchar; FR_SIZE]
) -> bool
{ serialize_to_buffer(field_element, &mut (unsafe { &mut *result })[..], FR_SIZE, "field element") }

#[no_mangle]
pub extern "C" fn zendoo_deserialize_field(
    field_bytes:    *const [c_uchar; FR_SIZE]
) -> *mut Fr
{ deserialize_from_buffer(&(unsafe { &*field_bytes })[..95], FR_SIZE) }

#[no_mangle]
pub extern "C" fn zendoo_field_free(field: *mut Fr)
{
    if field.is_null()  { return }
    drop(unsafe { Box::from_raw(field) });
}

//Keypair struct declaration

#[repr(C)]
pub struct KeyPair{
    pk: *mut G1Affine,
    sk: *mut Fs,
}

#[no_mangle]
pub extern "C" fn zendoo_keypair_free(keys: KeyPair){
    drop(unsafe { Box::from_raw(keys.pk) });
    drop(unsafe { Box::from_raw(keys.sk) });
}

//***********Pk functions****************
#[no_mangle]
pub extern "C" fn zendoo_get_pk_size_in_bytes() -> c_uint { G1_SIZE as u32 }

#[no_mangle]
pub extern "C" fn zendoo_serialize_pk(
    pk:            *const G1Affine,
    result:        *mut [c_uchar; G1_SIZE]
) -> bool
{ serialize_to_buffer(pk, &mut (unsafe { &mut *result })[..], G1_SIZE, "pk") }

#[no_mangle]
pub extern "C" fn zendoo_deserialize_pk(
    pk_bytes:    *const [c_uchar; G1_SIZE]
) -> *mut G1Affine
{ deserialize_from_buffer(&(unsafe { &*pk_bytes })[..], G1_SIZE) }

#[no_mangle]
pub extern "C" fn zendoo_pk_free(pk: *mut G1Affine)
{
    if pk.is_null()  { return }
    drop(unsafe { Box::from_raw(pk) });
}

//********************Sk functions***********************

#[no_mangle]
pub extern "C" fn zendoo_get_sk_size_in_bytes() -> c_uint { FS_SIZE as u32 }

#[no_mangle]
pub extern "C" fn zendoo_serialize_sk(
    sk:            *const Fs,
    result:        *mut [c_uchar; FS_SIZE]
) -> bool
{ serialize_to_buffer(sk, &mut (unsafe { &mut *result })[..], FS_SIZE, "sk") }

#[no_mangle]
pub extern "C" fn zendoo_deserialize_sk(
    sk_bytes:    *const [c_uchar; FS_SIZE]
) -> *mut Fs
{ deserialize_from_buffer(&(unsafe { &*sk_bytes })[..], FS_SIZE) }

#[no_mangle]
pub extern "C" fn zendoo_sk_free(sk: *mut Fs)
{
    if sk.is_null()  { return }
    drop(unsafe { Box::from_raw(sk) });
}

//********************SNARK functions********************

#[no_mangle]
pub extern "C" fn get_ginger_zk_proof_size() -> c_uint { GROTH_PROOF_SIZE as u32 }

#[no_mangle]
pub extern "C" fn serialize_ginger_zk_proof(
    zk_proof:       *const GingerProof,
    zk_proof_bytes: *mut [c_uchar; GROTH_PROOF_SIZE]
) -> bool { serialize_to_buffer(zk_proof, &mut (unsafe { &mut *zk_proof_bytes })[..], GROTH_PROOF_SIZE, "zk proof") }

#[no_mangle]
pub extern "C" fn deserialize_ginger_zk_proof(
    zk_proof_bytes: *const [c_uchar; GROTH_PROOF_SIZE]
) -> *mut GingerProof
{ deserialize_from_buffer(&(unsafe { &*zk_proof_bytes })[..], GROTH_PROOF_SIZE) }

#[no_mangle]
pub extern "C" fn verify_ginger_zk_proof
(
    vk_path:            *const u8,
    vk_path_len:        usize,
    zkp:                *const GingerProof,
    public_inputs:      *const *const Fr,
    public_inputs_len:  usize,
) -> bool
{
    //Read public inputs
    let public_inputs = match read_double_raw_pointer(public_inputs, public_inputs_len, "public input") {
        Some(public_inputs) => public_inputs,
        None => return false,
    };

    // Deserialize the proof
    let zkp = match read_raw_pointer(zkp, "zk_proof"){
        Some(zkp) => zkp,
        None => return false
    };

    //Load Vk
    let vk = match read_from_file(vk_path, vk_path_len, "vk"){
        Some(vk) => vk,
        None => return false
    };

    let pvk = prepare_verifying_key(&vk);

    //After computing pvk, vk is not needed anymore
    drop(vk);

    // Verify the proof
    match verify_proof(&pvk, &zkp, &public_inputs) {
        Ok(result) => result,
        Err(e) => {
            set_last_error(Box::new(e), CRYPTO_ERROR);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn ginger_zk_proof_free(zkp: *mut GingerProof)
{
    if zkp.is_null()  { return }
    drop(unsafe { Box::from_raw(zkp) });
}

//********************Poseidon hash functions********************

#[no_mangle]
pub extern "C" fn zendoo_compute_poseidon_hash(
    input:        *const *const Fr,
    input_len:    usize,
) -> *mut Fr
{
    //Read message
    let message = match read_double_raw_pointer(input, input_len, "field element") {
        Some(message) => message,
        None => return null_mut()
    };

    //Compute hash
    let hash = match FrHash::evaluate(message.as_slice()) {
        Ok(hash) => hash,
        Err(e) => return {
            set_last_error(e, CRYPTO_ERROR);
            null_mut()
        },
    };

    //Return pointer to hash
    Box::into_raw(Box::new(hash))

}

// ********************Merkle Tree functions********************
#[no_mangle]
pub extern "C" fn ginger_mt_new(
    leaves:        *const *const Fr,
    leaves_len:    usize,
) -> *mut GingerMerkleTree
{
    //Read leaves
    let leaves = match read_double_raw_pointer(leaves, leaves_len, "field element") {
        Some(leaves) => leaves,
        None => return null_mut()
    };

    //Generate tree and compute Merkle Root
    let gmt = match GingerMerkleTree::new(&leaves) {
        Ok(tree) => tree,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut()
        },
    };

    Box::into_raw(Box::new(gmt))
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_root(
    tree:   *const GingerMerkleTree,
) -> *mut Fr
{
    let tree = match read_raw_pointer(tree, "tree"){
        Some(tree) => tree,
        None => return null_mut()
    };
    let root = tree.root();
    Box::into_raw(Box::new(root))
}

#[no_mangle]
pub extern "C" fn ginger_mt_get_merkle_path(
    leaf:       *const Fr,
    leaf_index: usize,
    tree:       *const GingerMerkleTree,
) -> *mut GingerMerkleTreePath
{
    //Read tree
    let tree = match read_raw_pointer(tree, "tree"){
        Some(tree) => tree,
        None => return null_mut()
    };

    //Read leaf
    let leaf = match read_raw_pointer(leaf, "leaf"){
        Some(leaf) => leaf,
        None => return null_mut()
    };

    //Compute Merkle Path
    let mp = match tree.generate_proof(leaf_index, leaf) {
        Ok(path) => path,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut()
        },
    };

    Box::into_raw(Box::new(mp))
}

#[no_mangle]
pub extern "C" fn ginger_mt_verify_merkle_path(
    leaf:        *const Fr,
    merkle_root: *const Fr,
    path:        *const GingerMerkleTreePath,
) -> bool
{

    //Read path
    let path = match read_raw_pointer(path, "path"){
        Some(path) => path,
        None => return false
    };

    //Read leaf
    let leaf = match read_raw_pointer(leaf, "leaf"){
        Some(leaf) => leaf,
        None => return false
    };

    //Read root
    let root = match read_raw_pointer(merkle_root, "root"){
        Some(root) => root,
        None => return false
    };

    // Verify leaf belonging
    match path.verify(root, leaf) {
        Ok(true) => true,
        Ok(false) => false,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn ginger_mt_free(tree: *mut GingerMerkleTree) {
    if tree.is_null() { return }
    drop(unsafe { Box::from_raw(tree) });
}

#[no_mangle]
pub extern "C" fn ginger_mt_path_free(path: *mut GingerMerkleTreePath) {
    if path.is_null()  { return }
    drop(unsafe { Box::from_raw(path) });
}

// ********************Signature functions********************

#[no_mangle]
pub extern "C" fn zendoo_schnorr_keygen() -> KeyPair
{
    let mut rng = OsRng;
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
    KeyPair {
        pk: Box::into_raw(Box::new(pk.into_affine())),
        sk: Box::into_raw(Box::new(sk)),
    }
}

#[no_mangle]
pub extern "C" fn zendoo_schnorr_get_pk(
    sk: *const Fs
) -> *mut G1Affine
{
    let sk = match read_raw_pointer(sk, "schnorr sk"){
        Some(sk) => sk,
        None => return null_mut()
    };
    let pk = SchnorrSigScheme::get_public_key(sk);
    Box::into_raw(Box::new(pk.into_affine()))
}

#[no_mangle]
pub extern "C" fn zendoo_schnorr_key_verify(
    pk: *const G1Affine
) -> bool
{
    let pk = match read_raw_pointer(pk, "schnorr pk"){
        Some(pk) => pk,
        None => return false
    };
    SchnorrSigScheme::keyverify(&(pk.into_projective()))
}

#[no_mangle]
pub extern "C" fn zendoo_schnorr_sign(
    message:     *const *const Fr,
    message_len: usize,
    keypair:     KeyPair
) -> *mut SchnorrSig
{
    let mut rng = OsRng;

    //Read message as field elements
    let fes = match read_double_raw_pointer(message, message_len, "field element"){
        Some(fes) => fes,
        None => return null_mut()
    };

    let (pk, sk) = unsafe {(&*keypair.pk, &*keypair.sk)};

    //Sign message and return opaque pointer to sig
    match SchnorrSigScheme::sign(&mut rng, &pk.into_projective(), sk, fes.as_slice()) {
        Ok(sig) => Box::into_raw(Box::new(sig)),
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_schnorr_verify(
    message:     *const *const Fr,
    message_len: usize,
    pk:          *const G1Affine,
    sig:         *const SchnorrSig,
) -> bool
{
    //Read message as field elements
    let fes = match read_double_raw_pointer(message, message_len, "field element"){
        Some(fes) => fes,
        None => return false
    };

    //Read pk
    let pk = match read_raw_pointer(pk, "schnorr pk") {
        Some(pk) => pk,
        None => return false
    };

    //Read sig
    let sig = match read_raw_pointer(sig, "schnorr sig") {
        Some(sig) => sig,
        None => return false
    };

    //Verify sig
    match SchnorrSigScheme::verify(&pk.into_projective(), fes.as_slice(), sig) {
        Ok(result) => result,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_get_schnorr_sig_size_in_bytes() -> c_uint { SIG_SIZE as u32 }

#[no_mangle]
pub extern "C" fn zendoo_serialize_schnorr_sig(
    sig: *const SchnorrSig,
    result: *mut [c_uchar; SIG_SIZE],
) -> bool
{ serialize_to_buffer(sig, &mut (unsafe { &mut *result })[..], SIG_SIZE, "schnorr sig") }

#[no_mangle]
pub extern "C" fn zendoo_deserialize_schnorr_sig(
    sig_bytes: *const [c_uchar; SIG_SIZE]
) -> *mut SchnorrSig
{ deserialize_from_buffer(&(unsafe { &*sig_bytes })[..], SIG_SIZE) }

#[no_mangle]
pub extern "C" fn zendoo_schnorr_sig_free(sig: *mut SchnorrSig)
{
    if sig.is_null() { return }
    drop(unsafe{ Box::from_raw(sig) });
}

// ********************VRF functions********************

#[no_mangle]
pub extern "C" fn zendoo_ecvrf_keygen() -> KeyPair
{
    let mut rng = OsRng;
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
    KeyPair {
        pk: Box::into_raw(Box::new(pk.into_affine())),
        sk: Box::into_raw(Box::new(sk)),
    }
}

#[no_mangle]
pub extern "C" fn zendoo_ecvrf_get_pk(
    sk: *const Fs
) -> *mut G1Affine
{
    let sk = match read_raw_pointer(sk, "ecvrf sk"){
        Some(sk) => sk,
        None => return null_mut()
    };
    let pk = EcVrfScheme::get_public_key(sk);
    Box::into_raw(Box::new(pk.into_affine()))
}

#[no_mangle]
pub extern "C" fn zendoo_ecvrf_key_verify(
    pk: *const G1Affine
) -> bool
{
    let pk = match read_raw_pointer(pk, "ecvrf pk"){
        Some(pk) => pk,
        None => return false
    };
    SchnorrSigScheme::keyverify(&(pk.into_projective()))
}

#[no_mangle]
pub extern "C" fn zendoo_ecvrf_prove(
    message:     *const *const Fr,
    message_len: usize,
    keypair:     KeyPair
) -> *mut EcVrfProof
{
    let mut rng = OsRng;

    //Read message as field elements
    let fes = match read_double_raw_pointer(message, message_len, "field element"){
        Some(fes) => fes,
        None => return null_mut()
    };

    let (pk, sk) = unsafe {(&*keypair.pk, &*keypair.sk)};

    //Generate proof for message and return opaque pointer to proof
    match EcVrfScheme::prove(&mut rng, &VRF_GH_PARAMS, &pk.into_projective(), sk, fes.as_slice()) {
        Ok(proof) => Box::into_raw(Box::new(proof)),
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_ecvrf_proof_to_hash(
    message:     *const *const Fr,
    message_len: usize,
    pk:          *const G1Affine,
    proof:       *const EcVrfProof,
) -> *mut Fr
{
    //Read message as field elements
    let fes = match read_double_raw_pointer(message, message_len, "field element"){
        Some(fes) => fes,
        None => return null_mut()
    };

    //Read pk
    let pk = match read_raw_pointer(pk, "ecvrf pk") {
        Some(pk) => pk,
        None => return null_mut()
    };

    //Read proof
    let proof = match read_raw_pointer(proof, "ecvrf proof") {
        Some(proof) => proof,
        None => return null_mut()
    };

    //Verify proof and return VRF output
    match EcVrfScheme::proof_to_hash(&VRF_GH_PARAMS, &pk.into_projective(), fes.as_slice(), proof) {
        Ok(result) => Box::into_raw(Box::new(result)),
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn zendoo_get_ecvrf_proof_size_in_bytes() -> c_uint { VRF_PROOF_SIZE as u32 }

#[no_mangle]
pub extern "C" fn zendoo_serialize_ecvrf_proof(
    proof:  *const EcVrfProof,
    result: *mut [c_uchar; VRF_PROOF_SIZE],
) -> bool
{ serialize_to_buffer(proof, &mut (unsafe { &mut *result })[..], VRF_PROOF_SIZE, "ecvrf proof") }

#[no_mangle]
pub extern "C" fn zendoo_deserialize_ecvrf_proof(
    proof_bytes: *const [c_uchar; VRF_PROOF_SIZE]
) -> *mut EcVrfProof
{ deserialize_from_buffer(&(unsafe { &*proof_bytes })[..], VRF_PROOF_SIZE) }

#[no_mangle]
pub extern "C" fn zendoo_ecvrf_proof_free(proof: *mut EcVrfProof)
{
    if proof.is_null() { return }
    drop(unsafe{ Box::from_raw(proof) });
}

//*****Naive threshold sig circuit functions******

#[no_mangle]
pub extern "C" fn zendoo_create_naive_threshold_sig_proof (
    params_path:        *const u8,
    params_path_len:    usize,
    //Witnesses
    pks:                *const *const G1Affine,
    pks_len:            usize,
    sigs:               *const *const SchnorrSig,
    sigs_len:           usize,
    threshold:          *const Fr,
    b:                  *const Fr,

    //Public inputs
    message:            *const Fr,
    hash_commitment:    *const Fr, //H(H(pks), threshold)

    //Other
    n:                   usize,
) -> *mut GingerProof {

    //Load params from file
    let params = match read_from_file(params_path, params_path_len, "parameters"){
        Some(params) => params,
        None => return null_mut()
    };

    //Read pks and map them into Options
    let pks = match read_double_raw_pointer(pks, pks_len, "pk"){
        Some(pks) => pks.iter().map(|pk| Some(pk.into_projective())).collect::<Vec<_>>(),
        None => return null_mut()
    };

    //Read sigs and map them into Options
    let sigs = match read_double_raw_pointer(sigs, sigs_len, "sig") {
        Some(sigs) => sigs.iter().map(|&sig|Some(sig)).collect::<Vec<_>>(),
        None => return null_mut(),
    };

    //Read threshold
    let threshold = match read_raw_pointer(threshold, "threshold"){
        Some(threshold) => threshold,
        None => return null_mut(),
    };

    //Read b, convert to bits, skip the required leading zeros and map them into Options
    let b = match read_raw_pointer(b, "b"){
        Some(b) => b,
        None => return null_mut(),
    };

    let b = {
        let b_len = (n.next_power_of_two() as u64).trailing_zeros() as usize;
        let b_bits = b.write_bits();
        let to_skip = Fr::size_in_bits() - (b_len + 1);
        b_bits[to_skip..].to_vec().iter().map(|&b| Some(b)).collect::<Vec<_>>()
    };

    //Read message
    let message = match read_raw_pointer(message, "message"){
        Some(message) => message,
        None => return null_mut(),
    };

    //Read hash commitment
    let hash_commitment = match read_raw_pointer(hash_commitment, "hash commitment"){
        Some(hash) => hash,
        None => return null_mut(),
    };

    //Build circuit
    let c = NaiveTresholdSignature::<Fr>::new(
        pks, sigs, Some(*threshold), b, Some(*message), Some(*hash_commitment), n
    );

    //Create proof
    let mut rng = OsRng;
    match create_random_proof(c, &params, &mut rng) {
        Ok(proof) => Box::into_raw(Box::new(proof)),
        Err(_) => return null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn zendoo_compute_keys_hash_commitment(
    pks:        *const *const G1Affine,
    pks_len:    usize,
) -> *mut Fr
{

    //Read pks
    let pks_x = match read_double_raw_pointer(pks, pks_len, "pk") {
        Some(pks) => pks.iter().map(|&pk| pk.x).collect::<Vec<_>>(),
        None => return null_mut()
    };

    //Compute hash
    let hash = match FrHash::evaluate(pks_x.as_slice()) {
        Ok(hash) => hash,
        Err(e) => {
            set_last_error(e, CRYPTO_ERROR);
            return null_mut()
        },
    };

    //Return pointer to hash
    Box::into_raw(Box::new(hash))
}

//***************Test functions*******************

fn check_equal<T: Eq>(val_1: *const T, val_2: *const T) -> bool{
    let val_1 = unsafe{ &* val_1 };
    let val_2 = unsafe{ &* val_2 };
    val_1 == val_2
}

#[no_mangle]
pub extern "C" fn zendoo_get_random_field() -> *mut Fr {
    let mut rng = OsRng;
    let random_f = Fr::rand(&mut rng);
    Box::into_raw(Box::new(random_f))
}

#[no_mangle]
pub extern "C" fn zendoo_print_field(field: *const Fr){
    println!("{:?}", unsafe {&* field});
}

#[no_mangle]
pub extern "C" fn zendoo_field_assert_eq(
    field_1: *const Fr,
    field_2: *const Fr,
) -> bool { check_equal(field_1, field_2 )}

#[no_mangle]
pub extern "C" fn zendoo_get_random_pk() -> *mut G1Affine {
    let mut rng = OsRng;
    let random_g = G1Projective::rand(&mut rng);
    Box::into_raw(Box::new(random_g.into_affine()))
}

#[no_mangle]
pub extern "C" fn zendoo_pk_assert_eq(
    pk_1: *const G1Affine,
    pk_2: *const G1Affine,
) -> bool { check_equal(pk_1, pk_2) }

#[no_mangle]
pub extern "C" fn zendoo_schnorr_sig_assert_eq(
    sig_1: *const SchnorrSig,
    sig_2: *const SchnorrSig,
) -> bool { check_equal(sig_1, sig_2) }

#[no_mangle]
pub extern "C" fn zendoo_ecvrf_proof_assert_eq(
    proof_1: *const EcVrfProof,
    proof_2: *const EcVrfProof,
) -> bool { check_equal(proof_1, proof_2) }