#ifndef SIMPLE_CRYPTO_H_
#define SIMPLE_CRYPTO_H_

#include <string>

int request_receipts(const char *filename, std::string &req_orig);
int generate_receipts(const char *filename, const char *privatekey);
int verify_receipts(const char *filename, const char *publickey,
                    std::string &ver_orig);
std::string get_output_filename(const std::string &filename);

#endif  // SIMPLE_CRYPTO_H_
