/*
 * Bulletproofs包装器
 * 提供C ABI接口供Python调用
 */

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use rand::thread_rng;
use merlin::Transcript;
use std::os::raw::{c_char, c_int};

// Pedersen承诺函数
#[no_mangle]
pub extern "C" fn bp_pedersen_commit(
    value: u64,
    blinding: u64,
    out_commit: *mut c_char
) -> c_int {
    // 创建Pedersen生成元
    let pc_gens = PedersenGens::default();
    
    // 将值和盲化因子转换为标量
    let value_scalar = Scalar::from(value as u64);
    let blinding_scalar = Scalar::from(blinding as u64);
    
    // 生成承诺
    let commitment = pc_gens.commit(value_scalar, blinding_scalar);
    
    // 将承诺写入输出缓冲区
    unsafe {
        let commit_bytes = commitment.compress().to_bytes();
        std::ptr::copy_nonoverlapping(
            commit_bytes.as_ptr() as *const c_char,
            out_commit,
            commit_bytes.len()
        );
    }
    
    0 // 成功
}

// 范围证明生成函数
#[no_mangle]
pub extern "C" fn bp_range_proof_prove(
    value: u64,
    l: u64,
    u: u64,
    blinding: u64,
    out_commit: *mut c_char,
    out_proof: *mut c_char,
    out_proof_len: *mut usize
) -> c_int {
    // 创建生成元
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    
    // 将值和盲化因子转换为标量
    let value_scalar = Scalar::from(value as u64);
    let blinding_scalar = Scalar::from(blinding as u64);
    
    // 生成承诺
    let commitment = pc_gens.commit(value_scalar, blinding_scalar);
    
    // 将承诺写入输出缓冲区
    unsafe {
        let commit_bytes = commitment.compress().to_bytes();
        std::ptr::copy_nonoverlapping(
            commit_bytes.as_ptr() as *const c_char,
            out_commit,
            commit_bytes.len()
        );
    }
    
    // 生成范围证明
    let mut rng = thread_rng();
    let mut transcript = Transcript::new(b"RangeProof");
    let proof = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        value as u64,
        &blinding_scalar,
        64
    );
    
    match proof {
        Ok((proof, _commitments)) => {
            let proof_bytes = proof.to_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    proof_bytes.as_ptr() as *const c_char,
                    out_proof,
                    proof_bytes.len()
                );
                *out_proof_len = proof_bytes.len();
            }
            0 // 成功
        }
        Err(_) => 1 // 失败
    }
}

// 范围证明验证函数
#[no_mangle]
pub extern "C" fn bp_range_proof_verify(
    l: u64,
    u: u64,
    commit: *const c_char,
    proof: *const c_char,
    proof_len: usize
) -> c_int {
    // 创建生成元
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    
    // 从输入读取承诺
    let commit_bytes = unsafe {
        std::slice::from_raw_parts(commit as *const u8, 32)
    };
    
    let mut commitment_array = [0u8; 32];
    commitment_array.copy_from_slice(commit_bytes);
    let commitment = CompressedRistretto(commitment_array);
    
    // 从输入读取证明
    let proof_bytes = unsafe {
        std::slice::from_raw_parts(proof as *const u8, proof_len)
    };
    
    let proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return 1 // 失败
    };
    
    // 验证范围证明
    let mut transcript = Transcript::new(b"RangeProof");
    match proof.verify_single(&bp_gens, &pc_gens, &mut transcript, &commitment, 64) {
        Ok(_) => 0,  // 成功
        Err(_) => 1  // 失败
    }
}