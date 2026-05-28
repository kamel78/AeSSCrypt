use std::time::Instant;

use rand::Rng;

use crate::{ aes_ciphers::CipherName, aess::core::AeSSCipherCore, ccm::{aes_ccm::AesCcm, aes_ccm_256::AesCcm256}, gcm::{aes_gcm::AesGcm, aes_gcm_256::AesGcm256}, ocb::{aes_ocb::AesOcb, aes_ocb_256::AesOcb256}, galois_arithmetic::GF128};

//   Benchmaking time scalability of the proposed approach/AES-GCM/AES-CCM/AES-OCB with respect to security level (128 vs .256)             

pub fn bench_aes_gcm_scaling() {
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let aad = b"Additional authenticated data";
    let iterations = 500;

    // Message sizes in bytes (from 128B to 64KB)
    let sizes = [256, 512, 1024, 4096, 16384, 65536, 65536 * 2, 65536 * 3, 65536 * 4, 65536 * 5, 65536 * 6, 65536 * 7, 65536 * 8, 65536 * 9, 65536 * 10, 65536 * 11, 65536 * 12, 65536 * 13, 65536 * 14, 65536 * 15, 65536 * 16];

    println!("\n=== AES-GCM Scaling Benchmark ===");
    println!("Size (B), AES128_avg_µs, AES256_avg_µs, Δrel(%)");
    for &size in &sizes {
        let plaintext = vec![0x42u8; size];        
        // AES-GCM-128
        let key128 = rand::rng().random::<u128>(); 
        let gcm128 = AesGcm::new(key128);
        let mut lat128 = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let ciphertext = gcm128.encrypt(&nonce, &plaintext, aad);
            let duration = start.elapsed();
            lat128.push(duration.as_nanos());
            std::hint::black_box(&ciphertext);
        }
        let avg128: u128 = lat128.iter().sum::<u128>() / iterations as u128;

        // AES-GCM-256
        let key256_1 = rand::rng().random::<u128>(); 
        let key256_2 = rand::rng().random::<u128>(); 
        
        let gcm256 = AesGcm256::new(&[key256_1,key256_2]);

        let mut lat256 = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let ciphertext = gcm256.encrypt(&nonce, &plaintext, aad);
            let duration = start.elapsed();
            lat256.push(duration.as_nanos());
            std::hint::black_box(&ciphertext);
        }
        let avg256: u128 = lat256.iter().sum::<u128>() / iterations as u128;

        // Relative overhead Δrel = (T256 - T128)/T128 * 100
        let delta_rel = ((avg256 as f64 - avg128 as f64) / avg128 as f64) * 100.0;
        println!("{:>8}, {:>10.2}, {:>10.2}, {:>6.2}",size, avg128 as f64 / 1000.0, avg256 as f64 / 1000.0, delta_rel);
    }
}

pub fn bench_aes_ccm_scaling() {
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let aad = b"Additional authenticated data";
    let iterations = 500;
    // Message sizes in bytes (from 128B to 64KB)
    let sizes = [256, 512, 1024, 4096, 16384, 65536, 65536 * 2, 65536 * 3, 65536 * 4, 65536 * 5, 65536 * 6, 65536 * 7, 65536 * 8, 65536 * 9, 65536 * 10, 65536 * 11, 65536 * 12, 65536 * 13, 65536 * 14, 65536 * 15, 65536 * 16];
    println!("\n=== AES-CCM Scaling Benchmark ===");
    println!("Size (B), AES128_avg_µs, AES256_avg_µs, Δrel(%)");
    for &size in &sizes {
        let plaintext = vec![0x42u8; size];       
        // AES-CCM-128
        let key128 = rand::rng().random::<u128>(); 
        let gcm128 = AesCcm::new(key128);
        let mut lat128 = Vec::with_capacity(iterations);
        let tag_len = 16;
        for _ in 0..iterations {
            let start = Instant::now();
            let ciphertext = gcm128.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
            let duration = start.elapsed();
            lat128.push(duration.as_nanos());
            std::hint::black_box(&ciphertext);
        }
        let avg128: u128 = lat128.iter().sum::<u128>() / iterations as u128;

        // AES-CCM-256
        let key256_1 = rand::rng().random::<u128>(); 
        let key256_2 = rand::rng().random::<u128>();         
        let gcm256 = AesCcm256::new(&[key256_1,key256_2]);
        let mut lat256 = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let ciphertext = gcm256.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
            let duration = start.elapsed();
            lat256.push(duration.as_nanos());
            std::hint::black_box(&ciphertext);
        }
        let avg256: u128 = lat256.iter().sum::<u128>() / iterations as u128;

        // Relative overhead Δrel = (T256 - T128)/T128 * 100
        let delta_rel = ((avg256 as f64 - avg128 as f64) / avg128 as f64) * 100.0;
        println!("{:>8}, {:>10.2}, {:>10.2}, {:>6.2}",size, avg128 as f64 / 1000.0, avg256 as f64 / 1000.0, delta_rel);
    }
}

pub fn bench_aes_ocb_scaling() {
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let aad = b"Additional authenticated data";
    let iterations = 500;
    // Message sizes in bytes (from 128B to 64KB)
    let sizes = [256, 512, 1024, 4096, 16384, 65536, 65536 * 2, 65536 * 3, 65536 * 4, 65536 * 5, 65536 * 6, 65536 * 7, 65536 * 8, 65536 * 9, 65536 * 10, 65536 * 11, 65536 * 12, 65536 * 13, 65536 * 14, 65536 * 15, 65536 * 16];
    println!("\n=== AES-OCB Scaling Benchmark ===");
    println!("Size (B), AES128_avg_µs, AES256_avg_µs, Δrel(%)");
    for &size in &sizes {
        let plaintext = vec![0x42u8; size];       
        // AES-OCB-128
        let key128 = rand::rng().random::<u128>(); 
        let gcm128 = AesOcb::new(key128);
        let mut lat128 = Vec::with_capacity(iterations);
        let tag_len = 16;
        for _ in 0..iterations {
            let start = Instant::now();
            let ciphertext = gcm128.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
            let duration = start.elapsed();
            lat128.push(duration.as_nanos());
            std::hint::black_box(&ciphertext);
        }
        let avg128: u128 = lat128.iter().sum::<u128>() / iterations as u128;

        // AES-OCB-256
        let key256_1 = rand::rng().random::<u128>(); 
        let key256_2 = rand::rng().random::<u128>();        
        let gcm256 = AesOcb256::new(&[key256_1,key256_2]);
        let mut lat256 = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let ciphertext = gcm256.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
            let duration = start.elapsed();
            lat256.push(duration.as_nanos());
            std::hint::black_box(&ciphertext);
        }
        let avg256: u128 = lat256.iter().sum::<u128>() / iterations as u128;

        // Relative overhead Δrel = (T256 - T128)/T128 * 100
        let delta_rel = ((avg256 as f64 - avg128 as f64) / avg128 as f64) * 100.0;
        println!("{:>8}, {:>10.2}, {:>10.2}, {:>6.2}",size, avg128 as f64 / 1000.0, avg256 as f64 / 1000.0, delta_rel);
    }
}

pub fn bench_aes_aess_scaling() {
    let iterations = 500;
    // Message sizes in bytes (from 128B to 64KB)
    let sizes = [256, 512, 1024, 4096, 16384, 65536, 65536 * 2, 65536 * 3, 65536 * 4, 65536 * 5, 65536 * 6, 65536 * 7, 65536 * 8, 65536 * 9, 65536 * 10, 65536 * 11, 65536 * 12, 65536 * 13, 65536 * 14, 65536 * 15, 65536 * 16];
    println!("\n=== AES-AESS Scaling Benchmark ===");
    println!("Size (B), AES128_avg_µs, AES256_avg_µs, Δrel(%)");
    for &size in &sizes {
        let plaintext = vec![0x42u8; size];        
        // AES-AESS-128
        let key128 = GF128::random(); 
        let iv = GF128::random(); 
        let mut out1 = Vec::<GF128>::new();
        let mut aess128 = AeSSCipherCore::new(&plaintext,size,true,&mut out1,4,  CipherName::AES128);
        aess128.set_key_scheme(&[key128,key128], &iv);
        let mut lat128 = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = aess128.encrypt();
            let duration = start.elapsed();
            lat128.push(duration.as_nanos());
        }
        let avg128: u128 = lat128.iter().sum::<u128>() / iterations as u128;

        // AES-AESS-256
        let key256_1 = GF128::random();
        let key256_2 = GF128::random();
        let iv = GF128::random();
        let mut out1 = Vec::<GF128>::new();
        let mut aess256 = AeSSCipherCore::new(&plaintext,size,true, &mut out1,4,  CipherName::AES256);
        aess256.set_key_scheme(&[key256_1,key256_2], &iv);
        let mut lat256 = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = aess256.encrypt();
            let duration = start.elapsed();
            lat256.push(duration.as_nanos());
        }
        let avg256: u128 = lat256.iter().sum::<u128>() / iterations as u128;

        // Relative overhead Δrel = (T256 - T128)/T128 * 100
        let delta_rel = ((avg256 as f64 - avg128 as f64) / avg128 as f64) * 100.0;
        println!("{:>8}, {:>10.2}, {:>10.2}, {:>6.2}",size, avg128 as f64 / 1000.0, avg256 as f64 / 1000.0, delta_rel);
    }
}
