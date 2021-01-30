#include <stdio.h>

// #include <relic.h>

#include "base64.h"

/*
void print_pub_key(rsa_t pub) {
    
}

int rsa(void) {
    int code = STS_ERR;

    rsa_t pub, priv;
    uint8_t in[10], out[RELIC_BN_BITS / 8 + 1], h[MD_LEN];
    int i1, o1;
    int result;

    rsa_null(pub);
    rsa_null(priv);

    TRY {
        rsa_new(pub);
        rsa_new(priv);

        result = cp_rsa_gen(pub, priv, RELIC_BN_BITS);

        // Public Key components: n, e
        // Private Key components: d

        rand_bytes(in, 10);

        pub.


    } CATCH_ANY {
        ERROR(end);
    }

end:
    rsa_free(pub);
    rsa_free(priv);
}
*/

int main(void)
{
    char* raw = "padding tes";
    char output[BASE64_REQUIRED_LENGTH(11) + 1] = { 0 };
    base64_encode(raw, 11, output);

    puts(output);

    return 0;
}
