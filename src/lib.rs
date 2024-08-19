use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use once_cell::sync::OnceCell;
use machine_uid;
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rand::rngs::OsRng;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pyo3::prelude::*;

// openssl genrsa -out private_key.pem 2048
const PRIVATE_KEY_STR: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA1zUtpk2GSGNJzIdyYdEZWSftSHgQ2/7P2ptYF+fGEVRl2TPS
ioqOCS89qdQUeK/k1W10tkZJ+QuUBB/EH59yuhnYhUyJVtOoSB/fSEB8BOgJi2/K
iADvRpy7PcHDNRYPQLnqzmnVWq2qbk1NGZ3qgBz/cMi31SL7icTE5J2+EXVC4gyK
HIHEU3VuUncI91pVRcU4WFKBNli5RRC8og4F0ZN2sbIaKTWBt7muMNHftCsbVLWU
rbWy5UwgVJqaJsd/zPVj/j5zdoqnNiPyjEXvslYKraZh2+K49yauhK3zeTwnDaNh
LSqufQkSs6dKXd2cM0Ot5M4jqRxBAM2lI1QA2wIDAQABAoIBAQCkrV+qIyZ/G+Lr
7DVdnmi8LW5IBwA3p6ubx0VIvaV1u1RYOWyBcPaxFoIkA1JK66W6n5AwrmaKeQ6h
fUFRRWy/9WkWz3NEip/52NG98wIzqu8q0Ld1DOoL6YDqB+v9Ik03pUyE+L03Ly78
SpCV6p33vLjGsADjymoaiQR1QDOiHOZQyfgs83Fie0jGM0Z6NL1ibMQI/n1pU4vN
9pcDOFePrwMxPs/Q6JDyKqtrOGxjpgGb22iu23tAsTaxsWtK/qnSnmvZJsyT9Ylg
749z/+skKvccaZuF31UyH26HYs8PNvHvX2wMzqM/Z/5fM+jWAuizRXy5CGfLN19Q
Va/wJmLxAoGBAPJ+1+lRKwjlXM2mFJgFmWVAd4GmgxkxeQwWGWbtFuSuBcqzrH33
BVScwU218fmmGcfHvy3lfyMJSLopgvZoYyj9sfRQHc41nhf63rq+6r60J5rVSXes
wMaGqoLjWyLKhDKxLaih+0uVcIxQ+hiD8zTh24F0vv5ILdm9oVE4vSpTAoGBAOMx
TgjpdYCJWOVGLmuBWvdoEKxhB4LPVb6VROmRaz0smzsVUKZz926fHqzT5yTzX2sI
igONyboxSp5+uoX0hfm47cFO0/pkenNQ7iiwa54sdKwYVR1wV4bK22RN8K79o3ku
V2Qj1H7NVzSIxvlFKdZPe0FcDtXjiVIdYJbXSU5ZAoGAArdE98n+72SSO4Nmq6U0
aJvmOr+ArGGPd4Ev26VAImOIkRKeFfMUTjRLPfGRujgQBdrI21y8pcnO1LbuTpAw
vB7LRW84Rjz3flFC+Vh2DJi78NH+tqZqqk6Lzld5h9Q40tCFMGRQCjKsRgYKJwgj
Sy5UZQjHstVgHhYvnldCVx0CgYEAhIzTlmd+4os/jiSwGJDT3dydPbUuiKcmw5ab
Khppkrtfpcz9zN+D0MqNPxAyn2BOn0fQHdqvgy4W9vnBIT5UnCnErS+shT3yIy1o
hdzILPSK7Y0Uu6Q7rKzV62N9tNrOcXkUC5zL8V8kLcZPMEel7R9aLfvju+6Qw5PY
MqlQX6ECgYEAoIsL8A3BvIwrIjBL8u37mX7ddgFAus1Rjq+5y2CVbzN4B3YCLlR3
H2VlSQGJXsUI4vStxGYBdGUY/Mnm+bVQ3EZtgMRZbh7jrmLZOuB8MXO32caHoMii
0IP67W+8LXLdhDJ3uIzenP8PoDYkz2REU8g4r+mekQUJowgIi9z1nXs=
-----END RSA PRIVATE KEY-----";
const SALT: &str = "Rkns0kSVT520";


// 全局私钥实例
static PRIVATE_KEY: OnceCell<RsaPrivateKey> = OnceCell::new();

// 全局公钥实例，通过私钥生成
static PUBLIC_KEY: OnceCell<RsaPublicKey> = OnceCell::new();

fn md5_hash(input: &str) -> String {
    let digest = md5::compute(input);
    format!("{:x}", digest)
}

// 加密数据函数
pub fn rsa_encrypt(input: &str) -> String {
    let mut rng = OsRng;
    // 初始化私钥和公钥
    let private_key = PRIVATE_KEY.get_or_init(|| {
        RsaPrivateKey::from_pkcs1_pem(PRIVATE_KEY_STR).expect("failed to load private key")
    });

    let public_key = PUBLIC_KEY.get_or_init(|| {
        private_key.to_public_key()
    });

    // 加密数据
    let encrypted_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, format!("{}{}", input, SALT).as_bytes())
        .expect("failed to encrypt");
    STANDARD.encode(&encrypted_data)
}

fn verify_encrypted_data(encrypted_data_base64: &str, md5_guid: &str, private_key: &RsaPrivateKey) -> bool {
    // Base64 decode
    let encrypted_data = match STANDARD.decode(encrypted_data_base64) {
        Ok(data) => data,
        Err(_) => return false,
    };

    // RSA decrypt
    let decrypted_data = match private_key.decrypt(Pkcs1v15Encrypt, &encrypted_data) {
        Ok(data) => match String::from_utf8(data) {
            Ok(data_str) => data_str,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    // Remove SALT from decrypted data
    if decrypted_data.len() < SALT.len() {
        return false;
    }
    let decrypted_md5 = &decrypted_data[..decrypted_data.len() - SALT.len()];

    // Compare the decrypted MD5 hash with the provided MD5 hash
    decrypted_md5 == md5_guid
}

fn encrypt_and_save(root_dir: &str) {
    let machine_guid = machine_uid::get().unwrap();
    println!("Guid: {}", machine_guid);

    let md5_guid = md5_hash(&machine_guid);
    println!("MD5 of Guid: {}", md5_guid);

    let encrypted_data = rsa_encrypt(&md5_guid);
    println!("Encrypted data: {:?}", encrypted_data);

    let file_path = format!("{}/check.pem", root_dir);
    let mut file = File::create(&file_path).expect("Unable to create file");
    file.write_all(encrypted_data.as_bytes()).expect("Unable to write data");
}

fn check_validation(root_dir: &str) -> bool {
    let file_path = format!("{}/check.pem", root_dir);
    if !Path::new(&file_path).exists() {
        return false;
    }
    // 读取文件内容
    let message: String = fs::read_to_string(&file_path).expect("Unable to read data");

    // 获取mac
    let machine_guid = machine_uid::get().unwrap();
    println!("Guid: {}", machine_guid);

    let md5_guid = md5_hash(&machine_guid);
    println!("MD5 of Guid: {}", md5_guid);

    let private_key = PRIVATE_KEY.get_or_init(|| {
        RsaPrivateKey::from_pkcs1_pem(PRIVATE_KEY_STR).expect("failed to load private key")
    });

    // Verify encrypted data
    let is_valid = verify_encrypted_data(&message, &md5_guid, &private_key);
    println!("Is valid: {}", is_valid);
    is_valid
}

#[pyfunction]
pub fn check_validation_py(root_dir: &str) -> bool {
    check_validation(root_dir)
}

#[pyfunction]
pub fn gen_validation(root_dir: &str) {
    encrypt_and_save(root_dir)
}

#[pymodule]
#[pyo3(name = "rvalidate_extension")]
fn rvalidate_extension(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(check_validation_py, m)?)?;
    m.add_function(wrap_pyfunction!(gen_validation, m)?)?;
    Ok(())    
}
