#include <string.h>
#include <string>
#include <vector>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "simple_crypto.h"
#include "base64_light.h"

#ifdef _WIN32
#include <Windows.h>
#include <winsock.h>
extern "C" {
#include <openssl/applink.c>
}
#else
#include <arpa/inet.h>
#endif

#define DESKEY "havealook"

static unsigned char cbc_iv[8] = {'0', '1', 'A', 'B', 'a', 'b', '9', '8'};

typedef enum {
    GENERAL = 0,
    ECB,
} CRYPTO_MODE;

std::string des_encrypt(const std::string &cleartext, const std::string &key);
std::string des_decrypt(const std::string &ciphertext, const std::string &key);
char *rsa_encrypt(const unsigned char *str, const char *public_key_filename,
                  int &len);
char *rsa_decrypt(const unsigned char *str, const char *private_key_filename,
                  int &len);
bool get_cpu_info(char *strbuf_cpuid, int len);

void write_file(const char *filename, const char *content);
void read_file(const char *filename, char *content, const size_t len);

std::string des_encrypt(const std::string &cleartext, const std::string &key) {
    std::string strCipherText;
    CRYPTO_MODE mode = GENERAL;

    switch (mode) {
        case GENERAL:
        case ECB: {
            DES_cblock keyEncrypt;
            memset(keyEncrypt, 0, 8);

            if (key.length() <= 8)
                memcpy(keyEncrypt, key.c_str(), key.length());
            else
                memcpy(keyEncrypt, key.c_str(), 8);

            DES_key_schedule keySchedule;
            DES_set_key_unchecked(&keyEncrypt, &keySchedule);

            const_DES_cblock inputText;
            DES_cblock outputText;
            std::vector<unsigned char> vecCiphertext;
            unsigned char tmp[8];

            for (int i = 0; i < cleartext.length() / 8; i++) {
                memcpy(inputText, cleartext.c_str() + i * 8, 8);
                DES_ecb_encrypt(&inputText, &outputText, &keySchedule,
                                DES_ENCRYPT);
                memcpy(tmp, outputText, 8);

                for (int j = 0; j < 8; j++) vecCiphertext.push_back(tmp[j]);
            }

            if (cleartext.length() % 8 != 0) {
                int tmp1 = cleartext.length() / 8 * 8;
                int tmp2 = cleartext.length() - tmp1;
                memset(inputText, 0, 8);
                memcpy(inputText, cleartext.c_str() + tmp1, tmp2);

                DES_ecb_encrypt(&inputText, &outputText, &keySchedule,
                                DES_ENCRYPT);
                memcpy(tmp, outputText, 8);

                for (int j = 0; j < 8; j++) vecCiphertext.push_back(tmp[j]);
            }

            strCipherText.clear();
            strCipherText.assign(vecCiphertext.begin(), vecCiphertext.end());
        } break;
    }

    return strCipherText;
}

std::string des_decrypt(const std::string &ciphertext, const std::string &key) {
    std::string strClearText;
    CRYPTO_MODE mode = GENERAL;

    switch (mode) {
        case GENERAL:
        case ECB: {
            DES_cblock keyEncrypt;
            memset(keyEncrypt, 0, 8);

            if (key.length() <= 8)
                memcpy(keyEncrypt, key.c_str(), key.length());
            else
                memcpy(keyEncrypt, key.c_str(), 8);

            DES_key_schedule keySchedule;
            DES_set_key_unchecked(&keyEncrypt, &keySchedule);

            const_DES_cblock inputText;
            DES_cblock outputText;
            std::vector<unsigned char> vecCleartext;
            unsigned char tmp[8];

            for (int i = 0; i < ciphertext.length() / 8; i++) {
                memcpy(inputText, ciphertext.c_str() + i * 8, 8);
                DES_ecb_encrypt(&inputText, &outputText, &keySchedule,
                                DES_DECRYPT);
                memcpy(tmp, outputText, 8);

                for (int j = 0; j < 8; j++) vecCleartext.push_back(tmp[j]);
            }

            if (ciphertext.length() % 8 != 0) {
                int tmp1 = ciphertext.length() / 8 * 8;
                int tmp2 = ciphertext.length() - tmp1;
                memset(inputText, 0, 8);
                memcpy(inputText, ciphertext.c_str() + tmp1, tmp2);

                DES_ecb_encrypt(&inputText, &outputText, &keySchedule,
                                DES_DECRYPT);
                memcpy(tmp, outputText, 8);

                for (int j = 0; j < 8; j++) vecCleartext.push_back(tmp[j]);
            }

            strClearText.clear();
            strClearText.assign(vecCleartext.begin(), vecCleartext.end());
        } break;
    }

    return strClearText;
}

char *rsa_encrypt(const unsigned char *str, const char *public_key_filename,
                  int &len) {
    char *p_en = NULL;
    RSA *p_rsa = NULL;
    FILE *pf = NULL;
    int rsa_len = 0;

    do {
        if ((pf = fopen(public_key_filename, "rb")) == NULL) break;

        if ((p_rsa = PEM_read_RSA_PUBKEY(pf, NULL, NULL, NULL)) == NULL) break;

        rsa_len = RSA_size(p_rsa);
        p_en = static_cast<char *>(malloc(rsa_len + 1));
        memset(p_en, 0, rsa_len + 1);
        if ((len = RSA_public_encrypt(rsa_len, str, (unsigned char *)p_en,
                                      p_rsa, RSA_NO_PADDING)) < 0)
            break;

    } while (0);

    RSA_free(p_rsa);
    if (pf) fclose(pf);

    return p_en;
}

char *rsa_decrypt(const unsigned char *str, const char *private_key_filename,
                  int &len) {
    char *p_de = NULL;
    RSA *p_rsa = NULL;
    FILE *pf = NULL;
    int rsa_len = 0;

    do {
        if ((pf = fopen(private_key_filename, "rb")) == NULL) break;

        if ((p_rsa = PEM_read_RSAPrivateKey(pf, NULL, NULL, NULL)) == NULL)
            break;

        rsa_len = RSA_size(p_rsa);
        p_de = static_cast<char *>(malloc(rsa_len + 1));
        memset(p_de, 0, rsa_len + 1);
        if ((len = RSA_private_decrypt(rsa_len, str, (unsigned char *)p_de,
                                       p_rsa, RSA_NO_PADDING)) < 0)
            break;
    } while (0);

    RSA_free(p_rsa);
    if (pf) fclose(pf);

    return p_de;
}

#define SIZE 10000

bool get_cpu_info(char *strbuf_cpuid, int buflen) {
    bool bret = false;
#ifdef _WIN32
    const long MAX_COMMAND_SIZE = 10000;
    char szFetCmd[] = "wmic cpu get processorid";
    const std::string strEnSearch = "ProcessorId";
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    SECURITY_ATTRIBUTES sa;
    char szBuffer[MAX_COMMAND_SIZE + 1] = {0};
    std::string strBuffer;
    unsigned long count = 0;
    long ipos = 0;
    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    memset(&sa, 0, sizeof(sa));
    pi.hProcess = NULL;
    pi.hThread = NULL;
    si.cb = sizeof(STARTUPINFO);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    do {
        bret = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
        if (!bret) break;
        GetStartupInfo(&si);
        si.hStdError = hWritePipe;
        si.hStdOutput = hWritePipe;
        si.wShowWindow = SW_HIDE;
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        bret = CreateProcess(NULL, szFetCmd, NULL, NULL, TRUE, 0, NULL, NULL,
                             &si, &pi);
        if (!bret) break;
        WaitForSingleObject(pi.hProcess, 500 /*INFINITE*/);
        bret = ReadFile(hReadPipe, szBuffer, MAX_COMMAND_SIZE, &count, 0);
        if (!bret) {
            break;
        }
        bret = false;
        strBuffer = szBuffer;
        ipos = strBuffer.find(strEnSearch);
        if (ipos < 0) {
            break;
        } else {
            strBuffer = strBuffer.substr(ipos + strEnSearch.length());
        }
        memset(szBuffer, 0x00, sizeof(szBuffer));
        strcpy_s(szBuffer, strBuffer.c_str());
        int j = 0;
        for (int i = 0; i < strlen(szBuffer); i++) {
            if (szBuffer[i] != ' ' && szBuffer[i] != '\n' &&
                szBuffer[i] != '\r') {
                if (j < buflen) {
                    strbuf_cpuid[j] = szBuffer[i];
                    j++;
                }
            }
        }
        bret = true;

    } while (0);

    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
#else
    memset(strbuf_cpuid, 0, buflen);

    unsigned long s1 = 0;
    unsigned long s2 = 0;

    asm volatile(
        "movl $0x01, %%eax; \n\t"
        "xorl %%edx, %%edx; \n\t"
        "cpuid; \n\t"
        "movl %%edx, %0; \n\t"
        "movl %%eax, %1; \n\t"
        : "=m"(s1), "=m"(s2));
    if (0 == s1 && 0 == s2) return false;

    snprintf(strbuf_cpuid, buflen, "%08X%08X", htonl(s2), htonl(s1));

    bret = true;
#endif
    return bret;
}

void write_file(const char *filename, const char *content) {
    do {
        FILE *pf = fopen(filename, "w");
        if (!pf) break;

        const size_t len = strlen(content);
        fwrite(content, len, 1, pf);
        fclose(pf);
    } while (0);
}

void read_file(const char *filename, char *content, const size_t len) {
    do {
        FILE *pf = fopen(filename, "r");
        if (!pf) break;

        fread(content, len, 1, pf);
        fclose(pf);
    } while (0);
}

int request_receipts(const char *filename, std::string &req_orig) {
    int result = 0;
    char cpu_serial_num[128];
    memset(cpu_serial_num, 0, sizeof(cpu_serial_num));
    get_cpu_info(cpu_serial_num, sizeof(cpu_serial_num));
    std::string orig = std::string(cpu_serial_num, 64);

    std::string orig_desEN = des_encrypt(orig, DESKEY);

    char b64workbuf[1024] = {0};
    int b64_output_len = base64_encode(b64workbuf, (char *)orig_desEN.data(),
                                       orig_desEN.length());
    std::string orig_desEN_b64EN = std::string(b64workbuf, b64_output_len);

    req_orig = orig_desEN_b64EN;

    write_file(filename, orig_desEN_b64EN.c_str());
    return result;
}

int generate_receipts(const char *filename, const char *privatekey) {
    int result = 0;
    char *orig_desEN_rsaEN = NULL;
    char tmpbuf[10000] = {0};

    memset(tmpbuf, 0, sizeof(tmpbuf));
    read_file(filename, tmpbuf, 10000);

    std::string orig_desEN_b64EN = std::string(tmpbuf);

    std::string orig_desEN = orig_desEN_b64EN;

    int len = 0;
    orig_desEN_rsaEN =
        rsa_decrypt((unsigned char *)orig_desEN.c_str(), privatekey, len);

    std::string strtmp = std::string(orig_desEN_rsaEN, len);
    char b64workbuf[1024] = {0};
    int b64_output_len = base64_encode(b64workbuf, orig_desEN_rsaEN, len);
    std::string orig_desEN_rsaEN_b64EN =
        std::string(b64workbuf, b64_output_len);

    write_file(get_output_filename(filename).c_str(),
               orig_desEN_rsaEN_b64EN.c_str());

    if (orig_desEN_rsaEN) delete orig_desEN_rsaEN;
    return result;
}

int verify_receipts(const char *filename, const char *publickey,
                    std::string &ver_orig) {
    int result = 0;
    char *orig_desEN = NULL;
    char tmpbuf2[10000] = {0};

    memset(tmpbuf2, 0, 10000);
    read_file(filename, tmpbuf2, 10000);
    std::string orig_desEN_rsaEN_b64EN = std::string(tmpbuf2);

    char b64workbuf[1024] = {0};
    int b64_output_len =
        base64_decode(b64workbuf, (char *)orig_desEN_rsaEN_b64EN.data(),
                      orig_desEN_rsaEN_b64EN.length());
    std::string orig_desEN_rsaEN = std::string(b64workbuf, b64_output_len);

    int len = 0;
    orig_desEN =
        rsa_encrypt((unsigned char *)(orig_desEN_rsaEN.data()), publickey, len);

    ver_orig = orig_desEN;

    if (orig_desEN) delete orig_desEN;
    return result;
}

std::string get_output_filename(const std::string &filename) {
    size_t tmppos = filename.rfind('.');
    size_t len = filename.length();
    std::string another = filename;
    if (tmppos == std::string::npos)
        another += "_out";
    else {
        another = filename.substr(0, tmppos);
        another += "_out" + filename.substr(tmppos, len - tmppos);
    }
    return another;
}
