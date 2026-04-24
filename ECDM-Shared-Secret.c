#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * Выполняет протокол ECDH (Elliptic Curve Diffie-Hellman) на кривой secp256k1.
 *
 * Вычисляет общий секрет и записывает в буфер.
 * @param private_key Приватный ключ этой стороны
 * @param other_public_key Публичный ключ второй стороны
 * @param secret_out Буфер для хранения вычисленного общего секрета (минимум 32 байта).
 * @param secret_len_out Указатель для записи длины полученного секрета.
 *
 * @return 0 в случае успеха, -1 в случае ошибки.
 */
int ecdh_compute_shared_secret(
    EC_KEY *key,
    const EC_POINT *other_public,
    unsigned char *secret_out_buffer,
    int *secret_len_out
) {
    if (!key || !other_public || !secret_out_buffer || !secret_len_out){
        fprintf(stderr, "ECDH SHARED SECRET: передан NULL указатель\n");
        return -1;
    }
    int len = ECDH_compute_key(
        secret_out_buffer,
        32,
        other_public,
        key,
        NULL);
    if (len <= 0){
        fprintf(stderr, "ECDH SHARED SECRET: Ошибка подсчёта общего секрета\n");
        return -1;
    }
    *secret_len_out = len;
    return 0;
}

/**
 * Выводит ключ из shared_secret с помощью HKDF (SHA-256).
 *
 * @param shared_secret Входной общий секрет (например, из ECDH)
 * @param shared_secret_len Длина секрета
 * @param salt Соль (рекомендуется фиксированная или согласованная)
 * @param salt_len Длина соли
 * @param info Контекстная информация (например, "enc" или "sig")
 * @param info_len Длина info
 * @param out_key Буфер для выходного ключа (например, 32 байта)
 * @param out_len Желаемая длина ключа
 *
 * @return 0 при успехе, -1 при ошибке
 */
int hkdf_derive(
    const unsigned char *shared_secret,
    int shared_secret_len,
    const unsigned char *salt,
    int salt_len,
    const unsigned char *info,
    int info_len,
    unsigned char *out_key,
    int out_len
) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx){
        fprintf(stderr, "HKDF DERIVE: ошибка создания контекста\n");
        return -1;
    }
    
    if (EVP_PKEY_derive_init(pctx) <= 0){
        fprintf(stderr, "HKDF DERIVE: ошибка инициализации контекста\n");
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0){
        fprintf(stderr, "HKDF DERIVE: ошибка установки функции хеширования SHA256\n");
        return -1;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0){
        fprintf(stderr, "HKDF DERIVE: ошибка установки соли\n");
        return -1;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, shared_secret_len) <= 0){
        fprintf(stderr, "HKDF DERIVE: ошибка установки общего секрета\n");
        return -1;
    }
    
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0){
        fprintf(stderr, "HKDF DERIVE: ошибка установки добавочной информации\n");
        return -1;
    }
    
    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out_key, &len) <= 0){
        fprintf(stderr, "HRDF DERIVE: ошибка вывода ключа");
        return -1;
    }
    
    EVP_PKEY_CTX_free(pctx);
    return 0;
}