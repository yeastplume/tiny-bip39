extern crate bip39;

use ::bip39::{Bip39, Language};

#[test]
fn validate_12_english() {
    let test_mnemonic = "park remain person kitchen mule spell knee armed position rail grid ankle";

    let _ = match Bip39::from_mnemonic(test_mnemonic.to_string(), Language::English, "".to_string()) {
        Ok(b) => b,
        Err(_) => { assert!(false); return }
    };
}

#[test]
fn validate_15_english() {
    let test_mnemonic = "any paddle cabbage armor atom satoshi fiction night wisdom nasty they midnight chicken play phone";

    let _ = match Bip39::from_mnemonic(test_mnemonic.to_string(), Language::English, "".to_string()) {
        Ok(b) => b,
        Err(_) => { assert!(false); return }
    };
}

#[test]
fn validate_18_english() {
    let test_mnemonic = "soda oak spy claim best oppose gun ghost school use sign shock sign pipe vote follow category filter";

    let _ = match Bip39::from_mnemonic(test_mnemonic.to_string(), Language::English, "".to_string()) {
        Ok(b) => b,
        Err(_) => { assert!(false); return }
    };
}


#[test]
fn validate_21_english() {
    let test_mnemonic = "quality useless orient offer pole host amazing title only clog sight wild anxiety gloom market rescue fan language entry fan oyster";

    let _ = match Bip39::from_mnemonic(test_mnemonic.to_string(), Language::English, "".to_string()) {
        Ok(b) => b,
        Err(_) => { assert!(false); return }
    };
}


#[test]
fn validate_24_english() {
    let test_mnemonic = "always guess retreat devote warm poem giraffe thought prize ready maple daughter girl feel clay silent lemon bracket abstract basket toe tiny sword world";

    let _ = match Bip39::from_mnemonic(test_mnemonic.to_string(), Language::English, "".to_string()) {
        Ok(b) => b,
        Err(_) => { assert!(false); return }
    };
}
