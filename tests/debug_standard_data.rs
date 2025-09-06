use base64;
use hex;
use scram_with_sm3::{find_proofs_sm3, hash_password_sm3, HashAlgorithm, Sm3Hash};
use std::num::NonZeroU32;

#[test]
fn debug_scram_sm3_step_by_step() {
    println!("🔍 逐步调试 SCRAM-SM3 与标准数据的匹配");

    // 标准数据输入
    let username = "user";
    let password = "pencil";
    let client_nonce = "fyko+d2lbbFgONRv9qkxdawL";
    let server_nonce = "3rfcNHYJY1ZVvWVs7j";
    let combined_nonce = "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j";
    let salt_b64 = "QSXCR+Q6sek8bf92";
    let iterations = 4096;

    // 标准数据期望值
    let expected_salted_password =
        "4022203548292aef6e967d648f109689fcc1fe7168f5dafc4eafaa62efbacc7b";
    let expected_stored_key = "53c5003607f3a92a95373c3364366dd3fe7c64952707b3e68db092744417dab0";
    let expected_client_proof_b64 = "BiXytxl9C94jXkbIj/HESs79+GC45h515QpNO79uNA0=";

    println!("📋 输入数据:");
    println!("  username: {}", username);
    println!("  password: {}", password);
    println!("  client_nonce: {}", client_nonce);
    println!("  server_nonce: {}", server_nonce);
    println!("  combined_nonce: {}", combined_nonce);
    println!("  salt_b64: {}", salt_b64);
    println!("  iterations: {}", iterations);

    // 步骤1: 解码盐值
    let salt_bytes = base64::decode(salt_b64).unwrap();
    println!("\n🔍 步骤1: 盐值解码");
    println!("  salt_b64: {}", salt_b64);
    println!("  salt_hex: {}", hex::encode(&salt_bytes).to_uppercase());

    // 步骤2: 计算 SaltedPassword
    let iterations_nz = NonZeroU32::new(iterations as u32).unwrap();
    let salted_password = hash_password_sm3(password, iterations_nz, &salt_bytes);

    println!("\n🔍 步骤2: SaltedPassword 计算");
    println!("  password: '{}'", password);
    println!("  salt: {}", hex::encode(&salt_bytes));
    println!("  iterations: {}", iterations);
    println!(
        "  实际计算: {}",
        hex::encode(&salted_password).to_lowercase()
    );
    println!("  期望结果: {}", expected_salted_password);
    println!(
        "  匹配: {}",
        hex::encode(&salted_password).to_lowercase() == expected_salted_password
    );

    // 步骤3: 计算 ClientKey
    let client_key = Sm3Hash::hmac_sign(&salted_password, b"Client Key");
    println!("\n🔍 步骤3: ClientKey 计算");
    println!("  salted_password: {}", hex::encode(&salted_password));
    println!("  message: 'Client Key'");
    println!("  client_key: {}", hex::encode(&client_key));

    // 步骤4: 计算 StoredKey
    let stored_key = Sm3Hash::hash(&client_key);
    println!("\n🔍 步骤4: StoredKey 计算");
    println!("  client_key: {}", hex::encode(&client_key));
    println!("  实际计算: {}", hex::encode(&stored_key).to_lowercase());
    println!("  期望结果: {}", expected_stored_key);
    println!(
        "  匹配: {}",
        hex::encode(&stored_key).to_lowercase() == expected_stored_key
    );

    // 步骤5: 构造 AuthMessage
    let gs2header = "n,,";
    let client_first_bare = format!("n={},r={}", username, client_nonce);
    let server_first = format!("r={},s={},i={}", combined_nonce, salt_b64, iterations);
    let client_final_without_proof = format!(
        "c={},r={}",
        base64::encode(gs2header.as_bytes()),
        combined_nonce
    );
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );

    println!("\n🔍 步骤5: AuthMessage 构造");
    println!("  gs2header: '{}'", gs2header);
    println!("  client_first_bare: '{}'", client_first_bare);
    println!("  server_first: '{}'", server_first);
    println!(
        "  client_final_without_proof: '{}'",
        client_final_without_proof
    );
    println!("  auth_message: '{}'", auth_message);

    // 标准数据中的 AuthMessage
    let expected_auth_message = "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j";
    println!("  期望的auth_message: '{}'", expected_auth_message);
    println!("  匹配: {}", auth_message == expected_auth_message);

    // 步骤6: 计算 ClientSignature
    let client_signature = Sm3Hash::hmac_sign(&stored_key, auth_message.as_bytes());
    println!("\n🔍 步骤6: ClientSignature 计算");
    println!("  stored_key: {}", hex::encode(&stored_key));
    println!("  auth_message: '{}'", auth_message);
    println!("  client_signature: {}", hex::encode(&client_signature));

    // 步骤7: 计算 ClientProof
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    println!("\n🔍 步骤7: ClientProof 计算");
    println!("  client_key: {}", hex::encode(&client_key));
    println!("  client_signature: {}", hex::encode(&client_signature));
    println!("  client_proof (XOR): {}", hex::encode(&client_proof));
    println!(
        "  client_proof_b64: {}",
        base64::encode(&client_proof)
    );
    println!("  期望的client_proof_b64: {}", expected_client_proof_b64);
    println!(
        "  匹配: {}",
        base64::encode(&client_proof) == expected_client_proof_b64
    );

    // 使用我们的库函数验证
    println!("\n🔍 使用库函数验证:");
    let (lib_client_proof, _server_signature) = find_proofs_sm3(
        gs2header,
        &client_first_bare,
        &server_first,
        &salted_password,
        &combined_nonce,
    );
    println!(
        "  库函数计算的client_proof: {}",
        hex::encode(&lib_client_proof)
    );
    println!(
        "  库函数client_proof_b64: {}",
        base64::encode(&lib_client_proof)
    );

    // 检查是否有差异
    if hex::encode(&salted_password).to_lowercase() != expected_salted_password {
        println!("\n❌ SaltedPassword 不匹配，问题在 PBKDF2-SM3 实现");
    }
    if hex::encode(&stored_key).to_lowercase() != expected_stored_key {
        println!("\n❌ StoredKey 不匹配，问题在 HMAC-SM3 或 SM3 Hash 实现");
    }
    if auth_message != expected_auth_message {
        println!("\n❌ AuthMessage 不匹配，问题在消息构造");
    }
}
