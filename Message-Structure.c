#include <stdint.h>

typedef struct Message_s {
    uint8_t *encrypted_text;
    int text_len;
    uint8_t iv[12];
    uint8_t tag[16];
    char *sign;
    int sign_len;
    uint8_t *aad;
    int aad_len;
    uint8_t *public_key;
    int public_key_len;
} Message;
