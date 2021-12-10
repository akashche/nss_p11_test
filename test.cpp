/* 
 * File:   test.cpp
 * Author: alex
 *
 * Created on November 18, 2021, 10:03 PM
 */

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <array>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <tuple>
#include <vector>

#include <unistd.h>

#include <nss.h>
#include <pkcs11.h>
#include <secmod.h>

#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/dh.h>
#include <botan/dsa.h>
#include <botan/ecdsa.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>

#define FIPS_SLOT_ID 3

static CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY; 
static CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY; 
static CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY; 
static CK_KEY_TYPE aes_key_type = CKK_AES;
static CK_KEY_TYPE generic_secret_type = CKK_GENERIC_SECRET;
static CK_KEY_TYPE rsa_key_type = CKK_RSA;
static CK_KEY_TYPE ec_key_type = CKK_EC;
static CK_KEY_TYPE dsa_key_type = CKK_DSA;
static CK_KEY_TYPE dh_key_type = CKK_X9_42_DH;
static CK_ULONG aes_256_bytes = 256 >> 3;
static CK_BBOOL ck_true = CK_TRUE;
static CK_ULONG zero = 0;
static std::vector<CK_BYTE> ec_params_sec256 = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};


const std::array<char, 16> symbols = {
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}};


static std::string to_hex(std::vector<char> vec, const std::string& spacer="") {
    auto res = std::string();
    for (char ch : vec) {
        unsigned char uch = static_cast<unsigned char> (ch);
        res.push_back(symbols[static_cast<size_t> (uch >> 4)]);
        res.push_back(symbols[static_cast<size_t> (uch & 0x0f)]);
        res += spacer;
    }
    return res;
}

std::filesystem::path current_executable_dir() {
    auto exec = std::string();
    exec.resize(4096);
    ssize_t len = readlink("/proc/self/exe", exec.data(), exec.size());
    assert(len > 0);
    exec.resize(len);
    auto path = std::filesystem::path(exec);
    return path.parent_path();
}

static CK_FUNCTION_LIST_PTR get_function_list() {
    SECMODModuleList* mlist = SECMOD_GetDefaultModuleList();
    SECMODModule* mod = nullptr;
    for (; nullptr != mlist; mlist = mlist->next) {
        SECMODModule* mod = mlist->module;
       if (mod->isFIPS && mod->slotCount > 0) {
            return static_cast<CK_FUNCTION_LIST_PTR>(mod->functionList);
       } 
    }
    return nullptr;
}

static void digest_example(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session) {
    CK_MECHANISM mech;
    std::memset(std::addressof(mech), '\0', sizeof(mech));
    mech.mechanism = CKM_SHA256;
    CK_RV err_digest_init = fl->C_DigestInit(session, std::addressof(mech));
    assert(CKR_OK == err_digest_init);
    std::vector<char> vec = {'f', 'o', 'o', 'b', 'a', 'r'};
    CK_RV err_digest_update = fl->C_DigestUpdate(session, 
            reinterpret_cast<CK_BYTE_PTR>(vec.data()),
            static_cast<CK_ULONG>(vec.size()));
    assert(CKR_OK == err_digest_update);
    auto digest = std::vector<char>();
    digest.resize(32);
    CK_ULONG digest_len = static_cast<CK_ULONG>(digest.size());
    CK_RV err_digest_final = fl->C_DigestFinal(session,
            reinterpret_cast<CK_BYTE_PTR>(digest.data()),
            std::addressof(digest_len));
    assert(CKR_OK == err_digest_final);
    assert(32 == digest_len);
    assert("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2" == to_hex(digest));
}

template <typename T>
static CK_ATTRIBUTE create_attr(CK_ATTRIBUTE_TYPE type, T* value_ptr, size_t value_len) {
    CK_ATTRIBUTE attr;
    std::memset(std::addressof(attr), '\0', sizeof(attr));
    attr.type = type;
    attr.pValue = static_cast<CK_VOID_PTR>(value_ptr);
    attr.ulValueLen = static_cast<CK_ULONG>(value_len);
    return attr;
}

static CK_OBJECT_HANDLE generate_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session) {
    CK_MECHANISM mech;
    std::memset(std::addressof(mech), '\0', sizeof(mech));
    mech.mechanism = CKM_AES_KEY_GEN;

    auto templ = std::vector<CK_ATTRIBUTE>();
    templ.emplace_back(create_attr(CKA_CLASS, std::addressof(secret_key_class), sizeof(secret_key_class)));
    templ.emplace_back(create_attr(CKA_KEY_TYPE, std::addressof(aes_key_type), sizeof(aes_key_type)));
    templ.emplace_back(create_attr(CKA_VALUE_LEN, std::addressof(aes_256_bytes), sizeof(aes_256_bytes)));

    CK_OBJECT_HANDLE key = -1;
    CK_RV err_gen = fl->C_GenerateKey(session, std::addressof(mech), 
            templ.data(), static_cast<CK_ULONG>(templ.size()), std::addressof(key));
    assert(CKR_OK == err_gen);
    return key;
}

static std::vector<char> create_iv() {
    auto iv = std::vector<char>();
    iv.resize(16);
    for (char i = 0; i < 16; i++) {
        iv.push_back(i);
    }
    return iv;
}

static std::vector<char> encrypt(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE key, std::vector<char>& plain) {

    auto iv = create_iv();

    CK_MECHANISM mech;
    std::memset(std::addressof(mech), '\0', sizeof(mech));
    mech.mechanism = CKM_AES_CBC_PAD;
    mech.pParameter = static_cast<CK_VOID_PTR>(iv.data());

    CK_RV err_init = fl->C_EncryptInit(session, std::addressof(mech), key);
    assert(CKR_OK == err_init);
    
    auto enc = std::vector<char>();
    enc.resize(16 + plain.size());
    CK_ULONG enc_upd_len = static_cast<CK_ULONG>(enc.size());
    CK_RV err_update = fl->C_EncryptUpdate(
            session,
            reinterpret_cast<CK_BYTE_PTR>(plain.data()),
            static_cast<CK_ULONG>(plain.size()),
            reinterpret_cast<CK_BYTE_PTR>(enc.data()),
            std::addressof(enc_upd_len));
    assert(CKR_OK == err_update);

    CK_ULONG enc_final_len = static_cast<CK_ULONG>(enc.size() - static_cast<size_t>(enc_upd_len));
    CK_RV err_final = fl->C_EncryptFinal(
            session,
            reinterpret_cast<CK_BYTE_PTR>(enc.data() + static_cast<size_t>(enc_upd_len)),
            std::addressof(enc_final_len));
    assert(CKR_OK == err_final);

    enc.resize(static_cast<size_t>(enc_upd_len + enc_final_len));
    return enc;
}

static std::vector<char> decrypt(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE key, std::vector<char>& enc) {

    auto iv = create_iv();

    CK_MECHANISM mech;
    std::memset(std::addressof(mech), '\0', sizeof(mech));
    mech.mechanism = CKM_AES_CBC_PAD;
    mech.pParameter = static_cast<CK_VOID_PTR>(iv.data());

    CK_RV err_init = fl->C_DecryptInit(session, std::addressof(mech), key);
    assert(CKR_OK == err_init);

    auto plain = std::vector<char>();
    plain.resize(enc.size());
    CK_ULONG plain_upd_len = static_cast<CK_ULONG>(plain.size());
    CK_RV err_update = fl->C_DecryptUpdate(
            session,
            reinterpret_cast<CK_BYTE_PTR>(enc.data()),
            static_cast<CK_ULONG>(enc.size()),
            reinterpret_cast<CK_BYTE_PTR>(plain.data()),
            std::addressof(plain_upd_len));
    assert(CKR_OK == err_update);

    CK_ULONG plain_final_len = static_cast<CK_ULONG>(plain.size() - static_cast<size_t>(plain_upd_len));
    CK_RV err_final = fl->C_DecryptFinal(
            session,
            reinterpret_cast<CK_BYTE_PTR>(plain.data() + static_cast<size_t>(plain_upd_len)),
            std::addressof(plain_final_len));
    assert(CKR_OK == err_final);

    plain.resize(static_cast<size_t>(plain_upd_len + plain_final_len));
    return plain;
}

static CK_OBJECT_HANDLE import_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE import_key, std::vector<char>& plain_key, 
        CK_OBJECT_CLASS& imp_key_class, CK_KEY_TYPE& imp_key_type) {

    auto enc_key = encrypt(fl, session, import_key, plain_key);

    auto iv = create_iv();

    CK_MECHANISM mech;
    std::memset(std::addressof(mech), '\0', sizeof(mech));
    mech.mechanism = CKM_AES_CBC_PAD;
    mech.pParameter = static_cast<CK_VOID_PTR>(iv.data());

    auto templ = std::vector<CK_ATTRIBUTE>();
    templ.emplace_back(create_attr(CKA_CLASS, std::addressof(imp_key_class), sizeof(imp_key_class)));
    templ.emplace_back(create_attr(CKA_KEY_TYPE, std::addressof(imp_key_type), sizeof(imp_key_type)));
    templ.emplace_back(create_attr(CKA_SIGN, std::addressof(ck_true), sizeof(ck_true)));

    // https://dev-tech-crypto.mozilla.narkive.com/41uraGyV/how-should-i-handle-cka-netscape-db-for-gost-private-keys
    auto pub_key = std::vector<char>();
    if (CKK_EC == imp_key_type) {
        pub_key.resize(plain_key.size() - 73);
        // https://superuser.com/a/1465498
        assert(65 == pub_key.size());
        std:memcpy(pub_key.data(), plain_key.data() + 73, pub_key.size());
        templ.emplace_back(create_attr(CKA_NSS_DB, pub_key.data(), pub_key.size()));
    } else {
        templ.emplace_back(create_attr(CKA_NSS_DB, std::addressof(zero), 1));
    }

    CK_OBJECT_HANDLE key_hadle = -1;
    CK_RV err_unwrap = fl->C_UnwrapKey(
            session,
            std::addressof(mech),
            import_key,
            reinterpret_cast<CK_BYTE_PTR>(enc_key.data()),
            static_cast<CK_ULONG>(enc_key.size()),
            templ.data(),
            static_cast<CK_ULONG>(templ.size()),
            std::addressof(key_hadle));
    assert(CKR_OK == err_unwrap);

    return key_hadle;
}

static std::vector<char> export_key(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE export_key, CK_OBJECT_HANDLE key_handle) {

    auto iv = create_iv();

    CK_MECHANISM mech;
    std::memset(std::addressof(mech), '\0', sizeof(mech));
    mech.mechanism = CKM_AES_CBC_PAD;
    mech.pParameter = static_cast<CK_VOID_PTR>(iv.data());

    auto enc_key = std::vector<char>();
    enc_key.resize(4096);
    CK_ULONG len = static_cast<CK_ULONG>(enc_key.size());
    CK_RV err_wrap = fl->C_WrapKey(
            session,
            std::addressof(mech),
            export_key,
            key_handle,
            reinterpret_cast<CK_BYTE_PTR>(enc_key.data()),
            std::addressof(len));
    assert(CKR_OK == err_wrap);
    enc_key.resize(static_cast<size_t>(len));

    return decrypt(fl, session, export_key, enc_key);
}

static std::vector<char> generate_rsa(size_t size_bits) {
    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey key(rng, size_bits);
    auto sec_vec = Botan::PKCS8::BER_encode(key);
    auto vec = Botan::unlock(sec_vec);
    auto res = std::vector<char>();
    res.resize(vec.size());
    std::memcpy(res.data(), vec.data(), vec.size());
    return res;
}

static std::vector<char> generate_ecdsa(const std::string& curve="secp256r1") {
    Botan::AutoSeeded_RNG rng;
    Botan::EC_Group ec_group(curve);
    Botan::ECDSA_PrivateKey key(rng, ec_group);
    auto sec_vec = Botan::PKCS8::BER_encode(key);
    auto vec = Botan::unlock(sec_vec);
    auto res = std::vector<char>();
    res.resize(vec.size());
    std::memcpy(res.data(), vec.data(), vec.size());
    return res;
}

static std::vector<char> generate_dsa() {
    Botan::AutoSeeded_RNG rng;
    Botan::DL_Group dl_group("modp/ietf/3072");
    Botan::DSA_PrivateKey key(rng, dl_group);
    auto sec_vec = Botan::PKCS8::BER_encode(key);
    auto vec = Botan::unlock(sec_vec);
    auto res = std::vector<char>();
    res.resize(vec.size());
    std::memcpy(res.data(), vec.data(), vec.size());
    return res;
}

static std::vector<char> generate_dh() {
    Botan::AutoSeeded_RNG rng;
    Botan::DL_Group dl_group("modp/ietf/3072");
    Botan::DH_PrivateKey key(rng, dl_group);
    auto sec_vec = Botan::PKCS8::BER_encode(key);
    auto vec = Botan::unlock(sec_vec);
    auto res = std::vector<char>();
    res.resize(vec.size());
    std::memcpy(res.data(), vec.data(), vec.size());
    return res;
}

static std::string stringify_pkcs8(const std::vector<char>& key_in) {
    auto vec = std::vector<uint8_t>();
    vec.resize(key_in.size());
    std::memcpy(vec.data(), key_in.data(), key_in.size());
    Botan::DataSource_Memory mem(vec);
    auto key = Botan::PKCS8::load_key(mem);
    return Botan::PKCS8::PEM_encode(*key);
}

static std::vector<char> read_file(const std::string& rel_path) {
    auto dir = current_executable_dir();
    auto file = dir / rel_path;
    std::ifstream ifs(file, std::fstream::binary); 
    auto res = std::vector<char>((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
    return res;
}

static void write_file(const std::string& rel_path, const std::vector<char>& data) {
    auto dir = current_executable_dir();
    auto file = dir / rel_path;
    std::ofstream ofs(file, std::fstream::binary); 
    ofs.write(data.data(), data.size());
}

static std::tuple<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> 
generate_ec_pair(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session) {
    CK_MECHANISM mech;
    std::memset(std::addressof(mech), '\0', sizeof(mech));
    mech.mechanism = CKM_EC_KEY_PAIR_GEN;

    auto templ_pub = std::vector<CK_ATTRIBUTE>();
    templ_pub.emplace_back(create_attr(CKA_CLASS, std::addressof(public_key_class), sizeof(public_key_class)));
    templ_pub.emplace_back(create_attr(CKA_KEY_TYPE, std::addressof(ec_key_type), sizeof(ec_key_type)));
    templ_pub.emplace_back(create_attr(CKA_EC_PARAMS, ec_params_sec256.data(), ec_params_sec256.size()));

    auto templ_priv = std::vector<CK_ATTRIBUTE>();
    templ_pub.emplace_back(create_attr(CKA_CLASS, std::addressof(private_key_class), sizeof(private_key_class)));
    templ_pub.emplace_back(create_attr(CKA_KEY_TYPE, std::addressof(ec_key_type), sizeof(ec_key_type)));

    CK_OBJECT_HANDLE key_pub = -1;
    CK_OBJECT_HANDLE key_priv = -1;
    CK_RV err_gen = fl->C_GenerateKeyPair(
            session,
            std::addressof(mech), 
            templ_pub.data(),
            static_cast<CK_ULONG>(templ_pub.size()),
            templ_priv.data(),
            static_cast<CK_ULONG>(templ_priv.size()),
            std::addressof(key_pub),
            std::addressof(key_priv));
    assert(CKR_OK == err_gen);
    return { key_pub, key_priv };
}

static void get_attribute(CK_FUNCTION_LIST_PTR fl, CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE attr) {
    
    auto vec = std::vector<char>();
    vec.resize(16);
    auto att = create_attr(attr, vec.data(), vec.size());
    auto templ = std::vector<CK_ATTRIBUTE>();
    templ.emplace_back(att);
    
    CK_RV err = fl->C_GetAttributeValue(
            session,
            obj,
            templ.data(),
            static_cast<CK_ULONG>(templ.size()));
    //assert(CKR_OK == err);
    std::cout << err << std::endl;
    std::cout << to_hex(vec) << std::endl;        
}

int main(int argc, char** argv) {

    // NSS init
    PRUint32 flags = NSS_INIT_READONLY;
    SECStatus err_nssinit = NSS_Initialize("/etc/pki/nssdb", "", "", "pkcs11.txt", flags);
    assert(0 == err_nssinit);

    // function list
    CK_FUNCTION_LIST_PTR fl = get_function_list();
    assert(fl);

    // PKCS#11 init
    CK_RV err_init = fl->C_Initialize(nullptr);
    assert(CKR_CRYPTOKI_ALREADY_INITIALIZED == err_init);

    // slot
    CK_ULONG slot_count = 1;
    CK_SLOT_ID slot_id;
    CK_RV err_slot_list = fl->C_GetSlotList(CK_FALSE, std::addressof(slot_id), std::addressof(slot_count));
    assert(CKR_OK == err_slot_list);
 
    // session
    CK_SESSION_HANDLE session;
    CK_RV err_open_session = fl->C_OpenSession(slot_id, CKF_SERIAL_SESSION, nullptr, nullptr, std::addressof(session));
    assert(CKR_OK == err_open_session);

    // check digest
    digest_example(fl, session);

    // gen wrap/unwrap key
    auto wrap_key = generate_key(fl, session);
    assert(wrap_key > 0);

    {
        // encrypt
        std::vector<char> plain = {'f', 'o', 'o', 'b', 'a', 'r'};
        auto enc = encrypt(fl, session, wrap_key, plain);

        // decrypt
        auto dec = decrypt(fl, session, wrap_key, enc);
        assert("foobar" == std::string(dec.data(), dec.size()));
    }

    {
        // import generic secret
        auto plain_key = std::vector<char>();
        plain_key.resize(48);
        plain_key[42] = 42;
        auto imported_key = import_key(fl, session, wrap_key, plain_key, secret_key_class, generic_secret_type);
        assert(imported_key > 0);
        // export
        auto exported_key = export_key(fl, session, wrap_key, imported_key);
        assert(exported_key == plain_key);
    }

    {
        // import aes
        auto plain_key = std::vector<char>();
        plain_key.resize(32);
        plain_key[24] = 42;
        auto imported_key = import_key(fl, session, wrap_key, plain_key, secret_key_class, aes_key_type);
        assert(imported_key > 0);
        // export
        auto exported_key = export_key(fl, session, wrap_key, imported_key);
        assert(exported_key == plain_key);
        //std::cout << to_hex(exported_key) << std::endl;
    }

    {
        // import rsa
        auto plain_key = generate_rsa(2048);
        auto imported_key = import_key(fl, session, wrap_key, plain_key, private_key_class, rsa_key_type);
        assert(imported_key > 0);
        // export
        auto exported_key = export_key(fl, session, wrap_key, imported_key);
        assert(exported_key == plain_key);
    }

    {
        // import ecdsa
        auto plain_key = generate_ecdsa();
        auto imported_key = import_key(fl, session, wrap_key, plain_key, private_key_class, ec_key_type);
        assert(imported_key > 0);
        // export
        auto exported_key = export_key(fl, session, wrap_key, imported_key);
        assert(exported_key == plain_key);
    }

    {
        // import dsa
        auto plain_key = generate_dsa();
        auto imported_key = import_key(fl, session, wrap_key, plain_key, private_key_class, dsa_key_type);
        assert(imported_key > 0);
        // export
        auto exported_key = export_key(fl, session, wrap_key, imported_key);
        assert(exported_key == plain_key);
    }

    {
        // import dh
        auto plain_key = generate_dh();
        //std::cout << stringify_pkcs8(plain_key) << std::endl;
        //auto imported_key = import_key(fl, session, wrap_key, plain_key, private_key_class, dh_key_type);
    }

    {
        // generate ec
        auto [pub, priv] = generate_ec_pair(fl, session);
        //get_attribute(fl, session, priv, CKA_EC_PARAMS);
        //auto exported_pub = export_key(fl, session, wrap_key, pub);
        //write_file("exported_ec_pub.der", exported_pub);
        auto exported_priv = export_key(fl, session, wrap_key, priv);
        //write_file("ec_nss.der", exported_priv);
    }

    // close session
    CK_RV err_close_session = fl->C_CloseSession(session);
    assert(CKR_OK == err_close_session);

    std::cout << "success" << std::endl;
    return 0;
}

