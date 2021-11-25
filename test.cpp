/* 
 * File:   test.cpp
 * Author: alex
 *
 * Created on November 18, 2021, 10:03 PM
 */

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#include <nss.h>
#include <pkcs11.h>
#include <secmod.h>

#define FIPS_SLOT_ID 3

const std::array<char, 16> symbols = {
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}};


static std::string to_hex(std::vector<char> vec) {
    auto res = std::string();
    for (char ch : vec) {
        unsigned char uch = static_cast<unsigned char> (ch);
        res.push_back(symbols[static_cast<size_t> (uch >> 4)]);
        res.push_back(symbols[static_cast<size_t> (uch & 0x0f)]);
    }
    return res;
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

    // close session
    CK_RV err_close_session = fl->C_CloseSession(session);
    assert(CKR_OK == err_close_session);

    std::cout << "success" << std::endl;
    return 0;
}

