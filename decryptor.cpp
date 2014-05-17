//
// chrome-os-x-cookie-decryptor
//
// Modified from Chromium, Copyright 2014 The Chromium Authors. All rights reserved.
//

#include <iostream>
#include <string>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prtypes.h>

const int kCCBlockSizeAES128 = 16;
const int AES_BLOCK_SIZE = kCCBlockSizeAES128;

const char kSalt[] = "saltysalt";
const size_t kDerivedKeySizeInBits = 128;
const size_t kEncryptionIterations = 1003;
const char kEncryptionVersionPrefix[] = "v10";

std::string decrypt(PK11Context* context,
                    const std::string& input)
{
    std::string output;
    size_t output_len = input.size() + AES_BLOCK_SIZE;
    output.resize(output_len);
    uint8* output_data = reinterpret_cast<uint8*>(const_cast<char*>(output.data()));
    
    int input_len = input.size();
    uint8* input_data = reinterpret_cast<uint8*>(const_cast<char*>(input.data()));
    
    int op_len;
    SECStatus rv = PK11_CipherOp(context,
                                 output_data,
                                 &op_len,
                                 output_len,
                                 input_data,
                                 input_len);
    if (rv != SECSuccess) {
        std::cerr << "[-] Failed to decrypt data (PK11_CipherOp), err #" << PR_GetError() << std::endl;
        output.clear();
        return output;
    }
    
    unsigned int digest_len;
    rv = PK11_DigestFinal(context,
                          output_data + op_len,
                          &digest_len,
                          output_len - op_len);
    if (rv != SECSuccess) {
        std::cerr << "[-] Failed to decrypt data (PK11_DigestFinal), err #" << PR_GetError() << std::endl;
        output.clear();
        return output;
    }
    
    output.resize(op_len + digest_len);
    return output;
}

PK11SymKey* DeriveKeyFromPassword(const std::string& password,
                                  const std::string& salt,
                                  size_t iterations,
                                  size_t key_size_in_bits)
{
    if (salt.empty() || iterations == 0 || key_size_in_bits == 0) {
        std::cerr << "[-] Invalid arguments" << std::endl;
        return NULL;
    }
    
    SECItem password_item;
    password_item.type = siBuffer;
    password_item.data = reinterpret_cast<unsigned char*>(const_cast<char *>(password.data()));
    password_item.len = password.size();
    SECItem salt_item;
    salt_item.type = siBuffer;
    salt_item.data = reinterpret_cast<unsigned char*>(const_cast<char *>(salt.data()));
    salt_item.len = salt.size();
    SECOidTag cipher_algorithm = SEC_OID_AES_256_CBC;
    
    SECAlgorithmID* alg_id = PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2,
                                                         cipher_algorithm,
                                                         SEC_OID_HMAC_SHA1,
                                                         key_size_in_bits / 8,
                                                         iterations,
                                                         &salt_item);
    if (alg_id == NULL) {
        std::cerr << "[-] Failed to create SECAlgorithmID, err #" << PR_GetError() << std::endl;
        return NULL;
    }
    
    PK11SlotInfo* slot = PK11_GetInternalSlot();
    
    if (slot == NULL) {
        std::cerr << "[-] Failed to get slot info, err #" << PR_GetError() << std::endl;
        return NULL;
    }
    
    PK11SymKey* sym_key = PK11_PBEKeyGen(slot, alg_id, &password_item, 
                                         PR_FALSE, NULL);
    if (sym_key == NULL) {
        std::cerr << "[-] Failed to get key, err #" << PR_GetError() << std::endl;
        return NULL;
    }
    
    return sym_key;
}

std::string chrome_decrypt(const std::string& ciphertext,
                           const std::string& password)
{
    if (ciphertext.empty()) {
        return "";
    }
    
    if (password.empty()) {
        std::cerr << "[-] Keychain password required" << std::endl;
        return "";
    }
    
    if (ciphertext.find(kEncryptionVersionPrefix) != 0) {
        return ciphertext;
    }
    
    std::string raw_ciphertext = ciphertext.substr(strlen(kEncryptionVersionPrefix));
    std::string salt(kSalt);
    
    PK11SymKey* encryption_key = DeriveKeyFromPassword(password,
                                                       salt,
                                                       kEncryptionIterations,
                                                       kDerivedKeySizeInBits);
    std::string iv(kCCBlockSizeAES128, ' ');
    
    SECItem iv_item;
    iv_item.type = siBuffer;
    iv_item.data = reinterpret_cast<unsigned char*>(const_cast<char *>(iv.data()));
    iv_item.len = iv.size();
    SECItem* param = PK11_ParamFromIV(CKM_AES_CBC_PAD, &iv_item);
    
    PK11Context* context = PK11_CreateContextBySymKey(CKM_AES_CBC_PAD,
                                                      CKA_DECRYPT,
                                                      encryption_key, param);
    if (raw_ciphertext.size() % AES_BLOCK_SIZE != 0) {
        // Decryption will fail if the input is not a multiple of the block size.
        // PK11_CipherOp has a bug where it will do an invalid memory access before
        // the start of the input, so avoid calling it. (NSS bug 922780).
        std::cerr << "[-] NSS bug 922780" << std::endl;
        return "";
    }
    
    return decrypt(context, raw_ciphertext);
}

int main(int argc, const char * argv[])
{
    
    SECStatus rv;
    rv = NSS_NoDB_Init(".");
    if (rv != SECSuccess) {
        std::cerr << "[-] NSS initialization failed, err #" << PR_GetError() << std::endl;
        return NULL;
    }
    
    std::cout << chrome_decrypt("blob_from_sqlite_database", "password_from_keychain") << std::endl;
    
    return 0;
}

