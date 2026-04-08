#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

/**
 * Шифрование сообщения с использованием AES-256-GCM
 * 
 * @param plaintext - исходный текст для шифрования
 * @param plaintext_len - длина исходного текста
 * @param aad - дополнительные аутентифицированные данные (может быть NULL)
 * @param aad_len - длина AAD
 * @param enc_key - ключ шифрования (32 байта)
 * @param iv - вектор инициализации (12 байт) - должен быть случайным!
 * @param ciphertext - [выход] буфер для зашифрованного текста (должен быть достаточно большим)
 * @param tag - [выход] буфер для тега аутентификации (16 байт)
 * @return длина зашифрованного текста или -1 при ошибке
 */
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *enc_key,
                    const unsigned char *iv,
                    unsigned char *ciphertext,
                    unsigned char *tag) {
    
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;
    int ret = 0;
    
    // 1. Создание контекста шифрования
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Ошибка создания контекста шифрования\n");
        return -1;
    }
    
    // 2. Инициализация операции шифрования
    //    EVP_aes_256_gcm() - указывает алгоритм: AES с ключом 256 бит в режиме GCM
    //    NULL - движок (аппаратное ускорение), обычно NULL
    //    enc_key - ключ шифрования (32 байта)
    //    iv - вектор инициализации (12 байт - рекомендуется для GCM)
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, enc_key, iv);
    if (ret != 1) {
        fprintf(stderr, "Ошибка инициализации шифрования\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 3. Добавление AAD (Additional Authenticated Data)
    //    Эти данные будут аутентифицированы (защищены тегом), но НЕ зашифрованы
    //    NULL в качестве выходного буфера означает, что мы только "кормим" AAD в алгоритм
    //    len здесь не используется, но функция требует указатель
    if (aad && aad_len > 0) {
        ret = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
        if (ret != 1) {
            fprintf(stderr, "Ошибка добавления AAD\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
    }
    
    // 4. Шифрование данных
    //    ciphertext - буфер для зашифрованных данных
    //    ciphertext_len - сюда запишется количество зашифрованных байт
    //    plaintext - исходные данные
    //    plaintext_len - длина исходных данных
    ret = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    if (ret != 1) {
        fprintf(stderr, "Ошибка шифрования данных\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // 5. Завершение шифрования
    //    ciphertext + ciphertext_len - записываем остаток после предыдущих данных
    //    len - количество дописанных байт
    ret = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
    if (ret != 1) {
        fprintf(stderr, "Ошибка завершения шифрования\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    ciphertext_len += len;  // Увеличиваем общую длину на остаток
    
    // 6. Получение тега аутентификации
    //    EVP_CTRL_GCM_GET_TAG - управляющий код для получения тега GCM
    //    16 - размер тега в байтах (рекомендуется 16 для AES-GCM)
    //    tag - буфер для сохранения тега
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    if (ret != 1) {
        fprintf(stderr, "Ошибка получения тега GCM\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // Всё успешно, возвращаем длину зашифрованного текста
    ret = ciphertext_len;
    
    cleanup:
        // 7. Очистка контекста
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return ret;
}