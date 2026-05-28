use std::{io, process::exit, time::Instant};
use libraries::{aes_ciphers::CipherName, aess::core::AeSSCipherCore, benchmarks::{ microbench_aes::microbench_aes, scalability_benchmarks::*, 
                             sensitivity_benchmarks::{TestParam, sensitivity_bench, tag_sensitivity}, 
                             time_benchmarks::*}, galois_arithmetic::GF128};

pub fn threshold_bench(){
    let mut data = Vec::<u8>::new();
    data.resize(160000, 1);
    let mut results_by_th:[f32;30]=[0.0;30];
    let mut count=0;
    let mut out = Vec::<GF128>::new();
    let key = GF128::random();
    let iv = GF128::random();    
    for len in (10240..160000).step_by(1024){
    count+=1;
    for t in 2..18{
                let mut st = AeSSCipherCore::new(&data,len, true, &mut out,t,CipherName::AES128);
                st.set_key_scheme(&[key], &iv);
                let start: Instant = Instant::now();
                st.encrypt();
                let duration = start.elapsed();
                results_by_th[t]+=((len*1000000) as f32)/((duration.as_micros() as f32)*((1024*1024*1024) as f32));
                }
    }
    for t in 2..18{ results_by_th[t]/=count as f32;
    println!("t = {}: {:.3} GB/s",t,results_by_th[t]);
}}
                             
pub fn basic_bench(){
    let mut data = Vec::<u8>::new();
    let mut out = Vec::<GF128>::new();
    let targted_size : usize = 1500;
    data.resize(targted_size, 1);
        let iv = GF128::random();
        let key = GF128::random();
        let mut st = AeSSCipherCore::new(&data,targted_size, true, &mut out,4,CipherName::AES128);
        st.set_key_scheme(&[key], &iv);
        println!("{}", "-".repeat(100));
        println!("Benckmarking for the PRP '{}'",st.prp_cipher.name());
        // benchmark the proposed approach with the PRP
        let start: Instant = Instant::now();
        let tag = st.encrypt();
        let duration = start.elapsed();
        println!("Duration of the propsal = {:?}", duration);
        // Check Results of decryption correctness
        st.decrypt(tag,true);
        let out = st.get_bytes_out();
        let mut check =true;
        for i in 0..150{check &=out[i] == data[i];
        println!("{},{}",i,out[i] == data[i]);
        }
        println!("Check result correctness :{}",check);
        
    }
                           
fn main(){
    // basic_bench();
    // threshold_bench();
       
      loop {    println!("============================================================================");
                println!("Please enter a choice (1, 2, or 3) for the following routines, or 4 to exit:"); 
                println!("Please run in '--release' mode for accurate results.");
                println!("============================================================================");
                println!("(1)- Runtime bench-marking of several implemented schemes in 128bit level.");
                println!("(2)- Runtime bench-marking of several implemented schemes in 256bit level.");
                println!("(3)- Key and IV sensitivity benchmarking.");
                println!("(4)- Tag and authentication sensitivity benchmarking.");
                println!("(5)- Runtime scaling from 128bit to 256bit level.");
                println!("(6)- Microbenchmark AES 128/256.");
                println!("Enter 8 to leave ...");
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let choice1: u32 = match input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => {
                        println!("Invalid input. Please enter a number.");
                        return;
                    }
                };
                if choice1 == 8 {break;}
                match  choice1 { 1=> { 
                                        bench_aes_gcm_throughput();
                                        bench_aes_gcm_latency();
                                        bench_aes_ccm_throughput();
                                        bench_aes_ccm_latency();
                                        bench_aes_aess_latency();
                                        bench_aess_throughput();
                                        bench_aes_ocb_throughput();
                                        bench_aes_ocb_latency();
                                        bench_ascon_throughput();
                                        bench_ascon_latency();
                                        bench_sparkle_throughput();
                                        bench_sparkle_latency();
                                        bench_giftcofb_throughput();
                                        bench_giftcofb_latency();
                                     }
                                 2=> {  bench_aes_gcm_256_throughput();
                                        bench_aes_gcm_256_latency();
                                        bench_aes_ccm_256_throughput();
                                        bench_aes_ccm_256_latency();
                                        bench_aess_256_latency();
                                        bench_aes_aess_256_throughput();
                                        bench_aes_ocb_256_throughput();
                                        bench_aes_ocb_256_latency();
                                     }                              
                                 3=>{   sensitivity_bench(TestParam::KEY);
                                        sensitivity_bench(TestParam::IV)} ,
                                 4=>{   tag_sensitivity()   },
                                 5=> {  bench_aes_gcm_scaling();
                                        bench_aes_ccm_scaling();
                                        bench_aes_ocb_scaling();
                                        bench_aes_aess_scaling();
                                     }                        
                                 6=>{   microbench_aes()   },

                                 _ =>{}       
                                }
                }

      
}
