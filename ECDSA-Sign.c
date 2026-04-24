#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <stdlib.h>

/**
 * Подписывает данные с использованием ECDSA (secp256k1 через EVP).
 *
 * @param data данные для подписи
 * @param data_len длина данных
 * @param key EC_KEY с приватным ключом
 * @param sig_out [out] буфер под подпись (malloc внутри функции)
 * @param sig_len [out] длина подписи
 *
 * @return 0 при успехе, -1 при ошибке
 */
int ecdsa_sign(
    const unsigned char *data,
    int data_len,
    EC_KEY *key,
    unsigned char **sig_out,
    int *sig_len
) {
    if (!data || !key || !sig_out || !sig_len){
        fprintf(stderr, "ECDSA SIGN: Передан NULL указатель\n");
        return -1;
    }

    int ret = -1;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;

    *sig_out = NULL;
    *sig_len = 0;

    // EC_KEY → EVP_PKEY: Перевод ключа в универсальный формат для подписи 
    pkey = EVP_PKEY_new();
    if (!pkey){
        fprintf(stderr, "ECDSA SIGN: Ошибка создания ключа EVP\n");
        return -1;
    }

    if (EVP_PKEY_set1_EC_KEY(pkey, key) != 1){
        fprintf(stderr, "ECDSA SIGN: Ошибка перевода ключа EC в формат EVP\n");
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx){
        fprintf(stderr, "ECDSA SIGN: Ошибка создания контекста подписи\n");
        goto cleanup;
    }

    // Инициализация подписи (SHA-256 + ECDSA)
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1){
        fprintf(stderr, "ECDSA SIGN: Ошибка инициализации подписи\n");
        goto cleanup;
    }

    // Подписываем данные
    if (EVP_DigestSignUpdate(mdctx, data, data_len) != 1){
        fprintf(stderr, "ECDSA SIGN: Ошибка во время подписи данных\n");
        goto cleanup;
    }

    // Получаем размер подписи
    size_t len = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &len) != 1){
        fprintf(stderr, "ECDSA SIGN: Ошибка во время получения размера подписи\n");
        goto cleanup;
    }

    *sig_out = (unsigned char *)malloc(len);
    if (!*sig_out){
        fprintf(stderr, "ECDSA SIGN: Ошибка выделения памяти для буфера подписи\n");
        goto cleanup;
    }

    // Получаем подпись
    if (EVP_DigestSignFinal(mdctx, *sig_out, &len) != 1){
        fprintf(stderr, "ECDSA SIGN: Ошибка финальной обработки подписи\n");
        goto cleanup;
    }

    *sig_len = (int)len;
    ret = 0;

cleanup:
    if (ret != 0 && *sig_out) {
        free(*sig_out);
        *sig_out = NULL;
    }

    if (mdctx)
        EVP_MD_CTX_free(mdctx);

    if (pkey)
        EVP_PKEY_free(pkey);

    return ret;
}