use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use base32::{Alphabet, decode, encode};
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    secret: Option<String>,

    #[arg(short, long, default_value_t = 6)]
    digits: usize,

    #[arg(short, long, default_value_t = 10)]
    time_step: u64,

    #[arg(short, long, value_enum, default_value_t = HashAlgArg::SHA256)]
    algorithm: HashAlgArg
}

#[derive(Debug, Clone)]
pub enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

pub struct TOTP {
    secret: Vec<u8>,
    digits: usize,
    time_step: u64,
    t0: u64, 
    algorithm: HashAlgorithm,
}

impl TOTP {
    
    pub fn new(secret: Vec<u8>, digits: usize, time_step: u64, algorithm: HashAlgorithm) -> Self {
        TOTP {
            secret,
            digits,
            time_step,
            t0: 0,
            algorithm,
        }
    }

    pub fn from_base32(secret_base32: &str, digits: usize, time_step: u64, algorithm: HashAlgorithm) -> Result<Self, String> {
        let secret = decode(Alphabet::RFC4648 { padding: false }, secret_base32)
            .ok_or_else(|| "Failed to decode base32: invalid base32 string".to_string())?;
        
        Ok(TOTP::new(secret, digits, time_step, algorithm)) 
    }

    pub fn generate_current(&self) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_secs();

        self.generate_at(now)
    }

    pub fn generate_at(&self, timestamp: u64) -> Result<String, String> {
        let counter = (timestamp - self.t0) / self.time_step;
        
        self.generate_hotp(counter)


    }

    fn generate_hotp(&self, counter: u64) -> Result<String, String> {
        let counter_bytes = counter.to_be_bytes();

        let hash = match self.algorithm {
            HashAlgorithm::SHA1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&self.secret)
                    .map_err(|e| format!("Invalid key: {}", e))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            },
            HashAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
                    .map_err(|e| format!("Invalid key: {}", e))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            },
            HashAlgorithm::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(&self.secret)
                    .map_err(|e| format!("Invalid key: {}", e))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            },
            

        };

        let offset = (hash.last().unwrap() & 0x0f ) as usize;
        let binary = ((hash[offset] & 0x7f) as u32) << 24
            | (hash[offset + 1] as u32) << 16
            | (hash[offset + 2] as u32) << 8
            | (hash[offset + 3] as u32);

        let otp = binary % 10u32.pow(self.digits as u32);

        Ok(format!("{:0width$}", otp, width = self.digits))
    }

    pub fn verify(&self, code: &str, timestamp: u64, window: u64) -> bool {
        let counter = (timestamp - self.t0) / self.time_step;
        
        // Check within the time window
        for i in 0..=window {
            if let Ok(generated) = self.generate_hotp(counter - i) {
                if generated == code {
                    return true;
                }
            }
            if i > 0 {
                if let Ok(generated) = self.generate_hotp(counter + i) {
                    if generated == code {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn verify_current(&self, code: &str, window: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.verify(code, now, window)
    }

}

pub fn generate_secret(length: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.gen::<u8>()).collect()
}

pub fn secret_to_base32(secret: &[u8]) -> String {
    encode(Alphabet::RFC4648 { padding: false }, secret)
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum HashAlgArg {
    SHA1,
    SHA256,
    SHA512,
}

fn main() {

    let args = Args::parse();

    let (secret, _) = match args.secret {
        Some(secret) => {
            let decoded = decode(Alphabet::RFC4648 { padding: false }, &secret)
                .expect("Invalid base32 secret provided");
            println!("Decoded secret (base32): {}", secret);
            (decoded, secret)
        },
        None => {
            let secret = generate_secret(20);
            let secret_base32 = secret_to_base32(&secret);
            println!("Generated new secret (base32): {}", secret_base32);
            (secret, secret_base32)
        }
    };


    let algorithm = match args.algorithm {
        HashAlgArg::SHA1 => HashAlgorithm::SHA1,
        HashAlgArg::SHA256 => HashAlgorithm::SHA256,
        HashAlgArg::SHA512 => HashAlgorithm::SHA512,
    };
    
    let totp = TOTP::new(secret, args.digits, args.time_step, algorithm);
    
    let code = totp.generate_current().unwrap();
    println!("Current OTP: {}", code);
    
    let is_valid = totp.verify_current(&code, 1);
    println!("Code valid: {}\n\n", is_valid);
    
    let mut last_code = String::new();

    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let time_remaining = totp.time_step - (now % totp.time_step);
        
        let current_code = totp.generate_current().unwrap();
        
        if current_code != last_code {
            print!("\x1b[2K\r\x1b[1A\x1b[2K\r\x1b[1A\x1b[2K\r");
            println!("\nNew code: {} (valid for {} seconds)", current_code, time_remaining);
            last_code = current_code;
        }

        let bar_length = 30; 
        let filled_length = (bar_length as f64 * (time_remaining as f64 / totp.time_step as f64)) as usize;
        let bar = "|".repeat(bar_length - filled_length) + &"-".repeat(filled_length);
        print!("\r  [{}] {} seconds", bar, time_remaining);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        thread::sleep(Duration::from_secs(1));
    }
}
