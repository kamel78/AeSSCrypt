use crate::{aes_ciphers::CommonCipher, params_generation::galois_arithmetic::field::MAX_VECTOR_ELEMENTS};

use super:: GF128;
use smallvec::SmallVec;

#[derive( Clone, Debug)]
pub struct GF128Vector{
    pub elements:SmallVec<[GF128; MAX_VECTOR_ELEMENTS]>,
    pub true_size:usize
}

impl GF128Vector {

    pub fn new(true_size:usize)-> Self{
        let elements = core::array::from_fn(|_| GF128::from(0)).into();
        GF128Vector { elements , true_size}
    }

    pub fn random(true_size: usize) -> Self {
        let elements: SmallVec::<[GF128; MAX_VECTOR_ELEMENTS]> = core::array::from_fn(|_| GF128::random()).into();
        GF128Vector { elements, true_size }
    }  
    
   fn derive_iv(key: &GF128, iv: &GF128, index: u64, prp:&CommonCipher) -> GF128 {
        let mut mix = (*key ^ *iv).to_u128();
        mix = mix.rotate_left(11);
        mix ^= 0x9E3779B9u128.wrapping_shl(32) | 0x79B9D373u128; // Extended 32-bit constant to 128
        mix ^= index as u128;
        mix = mix.rotate_left(5);
        GF128::from(mix).prp_encrypt(prp)
    }

    pub fn vec_from_iv(key: &GF128, initial_iv: &GF128, threshold: usize,prp:&CommonCipher) -> Self {
        let elements: SmallVec::<[GF128; MAX_VECTOR_ELEMENTS]> = (0..2*threshold-1)
                .map(|j| Self::derive_iv(key, initial_iv, j as u64,prp))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            GF128Vector { elements, true_size: 2*threshold-1 }
        }

    pub fn alpha_from_iv(key: &GF128,initial_iv: &GF128,threshold: usize,prp :&CommonCipher) -> GF128 {
        Self::derive_iv(key,initial_iv,(2* threshold).try_into().unwrap(),prp)
    }
    
    pub fn beta_from_iv(key: &GF128,initial_iv: &GF128,threshold: usize,prp :&CommonCipher) -> GF128 {
        Self::derive_iv(key,initial_iv,(2 * threshold + 1).try_into().unwrap(),prp)
    }

    pub fn beta_vector(beta :&GF128,size: usize) -> GF128Vector {
        let mut result = GF128Vector::new(size);
        result.elements[0] = GF128::from(1);
        result.elements[1] = beta.clone();
        for i in 2..size{ result.elements[i] = result.elements[i-1].multiply(beta)} 
        result

    }

    pub fn inv_beta_vector(beta :&GF128,size: usize) -> GF128Vector {
        let mut result = GF128Vector::new(size);
        result.elements[0] = GF128::from(1);
        result.elements[1] = beta.invert();
        for i in 2..size{ result.elements[i] = result.elements[i-1].multiply(&result.elements[1])} 
        result
    }
}

