#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <fstream>
#include "simple_crypto.h"

int main(int argc, char* argv[]) {
    std::string c2s_filename = "seetatech_receipts";

    if (argc > 1) c2s_filename = std::string(argv[1]);

    std::string req_orig;
    std::string ver_orig;
    // called in client
    request_receipts(c2s_filename.c_str(), req_orig);
    printf("%s %d\n", req_orig.c_str(), req_orig.length());

    // called in seetatech
    //generate_receipts(c2s_filename.c_str(), "seetatech_rzt.key");

    // called in client
    verify_receipts(get_output_filename(c2s_filename).c_str(),
                    "seetatech_rzt_pub.key", ver_orig);
    printf("%s %d\n", ver_orig.c_str(), ver_orig.length());

    if (req_orig == ver_orig)
        printf("good\n");
    else
        printf("not good\n");

    exit(EXIT_SUCCESS);
}
