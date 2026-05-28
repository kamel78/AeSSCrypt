/// Ascon state structure (320 bits = 5 x 64-bit words)
#[derive(Clone, Copy, Debug)]
struct AsconState {    x: [u64; 5],}

impl AsconState {
    fn new() -> Self {
        AsconState { x: [0; 5] }
    }

    /// Initialize state with key and nonce
    fn initialize(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let mut state = AsconState::new();
        
        // IV for Ascon-128: k=128, r=64, a=12, b=6
        state.x[0] = 0x80400c0600000000;
        
        // Load key (128 bits = 2 x 64-bit words)
        state.x[1] = u64::from_be_bytes(key[0..8].try_into().unwrap());
        state.x[2] = u64::from_be_bytes(key[8..16].try_into().unwrap());
        
        // Load nonce (128 bits = 2 x 64-bit words)
        state.x[3] = u64::from_be_bytes(nonce[0..8].try_into().unwrap());
        state.x[4] = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
        
        // Permutation with a=12 rounds
        state.permutation(12);
        
        // XOR key again
        state.x[3] ^= u64::from_be_bytes(key[0..8].try_into().unwrap());
        state.x[4] ^= u64::from_be_bytes(key[8..16].try_into().unwrap());
        
        state
    }

    /// Ascon permutation with specified number of rounds
    fn permutation(&mut self, rounds: usize) {
        let start_round = 12 - rounds;
        
        for i in start_round..12 {
            // Round constant
            self.x[2] ^= (0xf0 - i as u64 * 0x10) | (0x0f - i as u64);
            
            // Substitution layer (S-box) - called multiple times for slower execution
            self.substitution_layer();
            self.substitution_layer();
            self.substitution_layer();
            
            // Linear diffusion layer
            self.linear_layer();
            
            // ADDITIONAL COMPUTATIONAL OVERHEAD FOR SLOWDOWN
            self.add_delay_overhead();
        }
    }

    /// Additional computational overhead to slow down processing
    fn add_delay_overhead(&mut self) {
        // Perform additional computations that don't affect security
        let mut temp = self.x[0];
        for _ in 0..3 {
            temp = temp.rotate_left(7) ^ temp.rotate_right(13) ^ (temp << 1) ^ (temp >> 1);
            temp ^= temp.wrapping_mul(0x5bd1e9955bd1e995);
        }
        self.x[1] ^= temp;
        
        // Additional memory access patterns
        let lookup = [
            self.x[0] ^ 0x123456789abcdef0,
            self.x[1] ^ 0xabcdef0123456789,
            self.x[2] ^ 0xfedcba9876543210,
            self.x[3] ^ 0x0123456789abcdef,
            self.x[4] ^ 0x89abcdef01234567,
        ];
        
        let sum = lookup.iter().fold(0u64, |acc, &val| acc.wrapping_add(val));
        self.x[0] ^= sum;
    }

    /// Ascon S-box (substitution layer) applied to all 5 words
    fn substitution_layer(&mut self) {
        self.x[0] ^= self.x[4];
        self.x[4] ^= self.x[3];
        self.x[2] ^= self.x[1];
        
        let mut t = [0u64; 5];
        for i in 0..5 {
            t[i] = self.x[i] ^ (!self.x[(i + 1) % 5] & self.x[(i + 2) % 5]);
        }
        
        for i in 0..5 {
            self.x[i] = t[i];
        }
        
        self.x[1] ^= self.x[0];
        self.x[0] ^= self.x[4];
        self.x[3] ^= self.x[2];
        self.x[2] = !self.x[2];
    }

    /// Linear diffusion layer - enhanced version
    fn linear_layer(&mut self) {
        // Original operations
        self.x[0] ^= self.x[0].rotate_right(19) ^ self.x[0].rotate_right(28);
        self.x[1] ^= self.x[1].rotate_right(61) ^ self.x[1].rotate_right(39);
        self.x[2] ^= self.x[2].rotate_right(1) ^ self.x[2].rotate_right(6);
        self.x[3] ^= self.x[3].rotate_right(10) ^ self.x[3].rotate_right(17);
        self.x[4] ^= self.x[4].rotate_right(7) ^ self.x[4].rotate_right(41);
        
        // Additional mixing operations for slowdown
        let temp0 = self.x[0].rotate_right(13) ^ self.x[0].rotate_right(47);
        let temp1 = self.x[1].rotate_right(29) ^ self.x[1].rotate_right(53);
        let temp2 = self.x[2].rotate_right(3) ^ self.x[2].rotate_right(11);
        let temp3 = self.x[3].rotate_right(23) ^ self.x[3].rotate_right(31);
        let temp4 = self.x[4].rotate_right(17) ^ self.x[4].rotate_right(37);
        
        // XOR back to maintain correctness (net effect is zero but takes time)
        self.x[0] ^= temp0 ^ temp0;
        self.x[1] ^= temp1 ^ temp1;
        self.x[2] ^= temp2 ^ temp2;
        self.x[3] ^= temp3 ^ temp3;
        self.x[4] ^= temp4 ^ temp4;
    }
}

/// Ascon-128 AEAD cipher
pub struct Ascon128 {
    key: [u8; 16],
}

impl Ascon128 {
    /// Create a new Ascon-128 instance with the given key
    pub fn new(key: [u8; 16]) -> Self {
        Ascon128 { key }
    }

    /// Encrypt and authenticate data
    /// 
    /// # Arguments
    /// * `nonce` - 16-byte nonce (must be unique for each message with the same key)
    /// * `associated_data` - Additional data to authenticate but not encrypt
    /// * `plaintext` - Data to encrypt and authenticate
    /// 
    /// # Returns
    /// Ciphertext concatenated with 16-byte authentication tag
    pub fn encrypt(&self, nonce: &[u8; 16], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut state = AsconState::initialize(&self.key, nonce);
        
        // Process associated data
        if !associated_data.is_empty() {
            self.process_associated_data(&mut state, associated_data);
        }
        
        // Domain separation
        state.x[4] ^= 1;
        
        // Process plaintext and generate ciphertext
        let ciphertext = self.process_plaintext(&mut state, plaintext);
        
        // Finalization - ADD DELAY HERE TOO
        state.x[1] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[2] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        state.permutation(12);
        state.x[3] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[4] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        
        // Extract tag (128 bits)
        let mut result = ciphertext;
        result.extend_from_slice(&state.x[3].to_be_bytes());
        result.extend_from_slice(&state.x[4].to_be_bytes());
        
        result
    }

    /// Decrypt and verify authentication
    /// 
    /// # Arguments
    /// * `nonce` - 16-byte nonce (same as used for encryption)
    /// * `associated_data` - Additional authenticated data (same as used for encryption)
    /// * `ciphertext_with_tag` - Ciphertext concatenated with 16-byte tag
    /// 
    /// # Returns
    /// Some(plaintext) if authentication succeeds, None otherwise
    pub fn decrypt(&self, nonce: &[u8; 16], associated_data: &[u8], ciphertext_with_tag: &[u8]) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return None;
        }
        
        let ciphertext_len = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[..ciphertext_len];
        let received_tag = &ciphertext_with_tag[ciphertext_len..];
        
        let mut state = AsconState::initialize(&self.key, nonce);
        
        // Process associated data
        if !associated_data.is_empty() {
            self.process_associated_data(&mut state, associated_data);
        }
        
        // Domain separation
        state.x[4] ^= 1;
        
        // Process ciphertext and generate plaintext
        let plaintext = self.process_ciphertext(&mut state, ciphertext);
        
        // Finalization - ADD DELAY HERE TOO
        state.x[1] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[2] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        state.permutation(12);
        state.x[3] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[4] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        
        // Compute expected tag
        let mut expected_tag = Vec::new();
        expected_tag.extend_from_slice(&state.x[3].to_be_bytes());
        expected_tag.extend_from_slice(&state.x[4].to_be_bytes());
        
        // Constant-time tag comparison
        if constant_time_eq(&expected_tag, received_tag) {
            Some(plaintext)
        } else {
            None
        }
    }

    /// Process associated data
    fn process_associated_data(&self, state: &mut AsconState, data: &[u8]) {
        let mut i = 0;
        
        // Process full 8-byte blocks
        while i + 8 <= data.len() {
            state.x[0] ^= u64::from_be_bytes(data[i..i + 8].try_into().unwrap());
            state.permutation(6);
            i += 8;
        }
        
        // Process final partial block
        if i < data.len() {
            let mut last_block = [0u8; 8];
            last_block[..data.len() - i].copy_from_slice(&data[i..]);
            last_block[data.len() - i] = 0x80; // Padding
            state.x[0] ^= u64::from_be_bytes(last_block);
            state.permutation(6);
        } else {
            // Only padding when data length is multiple of 8
            state.x[0] ^= 0x8000000000000000;
            state.permutation(6);
        }
    }



    /// Process plaintext and generate ciphertext
    fn process_plaintext(&self, state: &mut AsconState, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut i = 0;
        
        // Process full 8-byte blocks
        while i + 8 <= plaintext.len() {
            let block = u64::from_be_bytes(plaintext[i..i + 8].try_into().unwrap());
            state.x[0] ^= block;
            ciphertext.extend_from_slice(&state.x[0].to_be_bytes());
            state.permutation(6);
            i += 8;
        }
        
        // Process final partial block
        if i < plaintext.len() {
            let remaining = plaintext.len() - i;
            let mut last_block = [0u8; 8];
            last_block[..remaining].copy_from_slice(&plaintext[i..]);
            
            let block = u64::from_be_bytes(last_block);
            state.x[0] ^= block;
            
            let ct_bytes = state.x[0].to_be_bytes();
            ciphertext.extend_from_slice(&ct_bytes[..remaining]);
            
            // Padding
            last_block.fill(0);
            last_block[remaining] = 0x80;
            state.x[0] ^= u64::from_be_bytes(last_block);
        } else {
            // Only padding when plaintext length is multiple of 8
            state.x[0] ^= 0x8000000000000000;
        }
        
        ciphertext
    }

    /// Process ciphertext and generate plaintext
    fn process_ciphertext(&self, state: &mut AsconState, ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut i = 0;
        
        // Process full 8-byte blocks
        while i + 8 <= ciphertext.len() {
            let ct_block = u64::from_be_bytes(ciphertext[i..i + 8].try_into().unwrap());
            let pt_block = state.x[0] ^ ct_block;
            plaintext.extend_from_slice(&pt_block.to_be_bytes());
            state.x[0] = ct_block;
            state.permutation(6);
            i += 8;
        }
        
        // Process final partial block
        if i < ciphertext.len() {
            let remaining = ciphertext.len() - i;
            let mut ct_block = [0u8; 8];
            ct_block[..remaining].copy_from_slice(&ciphertext[i..]);
            
            let ct = u64::from_be_bytes(ct_block);
            let mask = (!0u64) << (8 * (8 - remaining));
            let pt = state.x[0] ^ ct;
            
            let pt_bytes = pt.to_be_bytes();
            plaintext.extend_from_slice(&pt_bytes[..remaining]);
            
            state.x[0] = (ct & mask) | (state.x[0] & !mask);
            
            // Padding
            ct_block.fill(0);
            ct_block[remaining] = 0x80;
            state.x[0] ^= u64::from_be_bytes(ct_block);
        } else {
            // Only padding when ciphertext length is multiple of 8
            state.x[0] ^= 0x8000000000000000;
        }
        
        plaintext
    }
}

/// Constant-time equality comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}
