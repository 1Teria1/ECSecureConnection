#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include "Message-Structure.c"
#include "Key-Generation.c"
#include "AES-256-GCM-cypher.c"
#include "ECDM-Shared-Secret.c"


int main() {
    EC_KEY *alice = NULL;
    EC_KEY *bob = NULL;

    unsigned char alice_secret[32];
    unsigned char bob_secret[32];
    int alice_secret_len = 0;
    int bob_secret_len = 0;

    unsigned char alice_enc_key[32];
    unsigned char bob_enc_key[32];

    const unsigned char salt[] = "fixed_salt";

    Message msg = {0};

    // 1. Генерация ключей
    if (generate_ec_keypair(&alice) != 0 || generate_ec_keypair(&bob) != 0) {
        printf("Ошибка генерации ключей\n");
        return 1;
    }
    printf("Ключи успешно сгенерированы:\n");
    printf("Bob: Private %, Public");

    // 2. Обмен публичными ключами
    const EC_POINT *alice_pub = EC_KEY_get0_public_key(alice);
    const EC_POINT *bob_pub = EC_KEY_get0_public_key(bob);

    // 3. ECDH
    if (ecdh_compute_shared_secret(alice, bob_pub, alice_secret, &alice_secret_len) != 0 ||
        ecdh_compute_shared_secret(bob, alice_pub, bob_secret, &bob_secret_len) != 0) {
        printf("Ошибка ECDH\n");
        return 1;
    }
    printf("Общий секрет успешно подсчитан\n");

    if (memcmp(alice_secret, bob_secret, alice_secret_len) != 0) {
        printf("Секреты не совпадают!\n");
        return 1;
    }

    printf("Общий секрет совпадает\n");

    // 4. HKDF → ключи
    if (hkdf_derive(alice_secret, alice_secret_len, salt, sizeof(salt),
                    (unsigned char*)"enc", 3, alice_enc_key, 32) != 0 ||
        hkdf_derive(bob_secret, bob_secret_len, salt, sizeof(salt),
                    (unsigned char*)"enc", 3, bob_enc_key, 32) != 0) {
        printf("Ошибка HKDF\n");
        return 1;
    }

    // 5. Алиса шифрует сообщение
    const char *message = "Hello Bob!";
    msg.encrypted_text = malloc(128);

    if (!msg.encrypted_text) {
        printf("Ошибка выделения памяти\n");
        return 1;
    }

    if (RAND_bytes(msg.iv, 12) != 1) {
        printf("Ошибка генерации IV\n");
        return 1;
    }

    msg.text_len = aes_gcm_encrypt(
        (unsigned char*)message,
        strlen(message),
        NULL,
        0,
        alice_enc_key,
        msg.iv,
        msg.encrypted_text,
        msg.tag
    );

    if (msg.text_len < 0) {
        printf("Ошибка шифрования\n");
        return 1;
    }
    printf("Сообщение Алисы успешно защифровано\n");

    // 6. AAD (в примере нет)
    msg.aad = NULL;
    msg.aad_len = 0;

    // 7. Сериализация публичного ключа Алисы
    const EC_GROUP *group = EC_KEY_get0_group(alice);

    msg.public_key_len = EC_POINT_point2oct(
        group,
        alice_pub,
        POINT_CONVERSION_UNCOMPRESSED,
        NULL,
        0,
        NULL
    );

    msg.public_key = malloc(msg.public_key_len);

    if (!msg.public_key) {
        printf("Ошибка выделения памяти\n");
        return 1;
    }

    if (EC_POINT_point2oct(
            group,
            alice_pub,
            POINT_CONVERSION_UNCOMPRESSED,
            msg.public_key,
            msg.public_key_len,
            NULL
        ) == 0) {
        printf("Ошибка сериализации ключа\n");
        return 1;
    }

    // 8. Подпись (заглушка)
    msg.sign = NULL;
    msg.sign_len = 0;

    printf("Сообщение подготовлено и записано в структуру Message\n");

    // Очистка
    free(msg.encrypted_text);
    free(msg.public_key);

    EC_KEY_free(alice);
    EC_KEY_free(bob);

    return 0;
}