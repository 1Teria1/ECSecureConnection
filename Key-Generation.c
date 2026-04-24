#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * Генерирует пару EC-ключей (приватный + публичный) на кривой secp256k1.
 *
 * Как это работает:
 * 1. Выбирается эллиптическая кривая (здесь secp256k1).
 * 2. Генерируется случайный приватный ключ (скаляр d).
 *    - Для этого используется криптографически стойкий генератор случайных чисел OpenSSL.
 * 3. Вычисляется публичный ключ как точка на кривой:
 *      Q = d * G
 *    где G — генератор кривой.
 *
 * Важно:
 * - Приватный ключ должен храниться в секрете и никогда не передаваться.
 * - Публичный ключ можно передавать другим сторонам.
 * - OpenSSL автоматически использует безопасный RNG (через RAND_bytes).
 *
 * @param out_key Указатель, куда будет записан созданный EC_KEY*
 *
 * @return 0 при успехе, -1 при ошибке
 */
int generate_ec_keypair(EC_KEY **out_key) {
    if (!out_key){
        fprintf(stderr, "GENERATE EC KEYPAIR: Передан NULL указатель\n");
        return -1;
    }

    EC_KEY *key = NULL;

    // 1. Создаём объект ключа для кривой secp256k1
    key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key){
        fprintf(stderr, "GENERATE EC KEYPAIR: Ошибка создания объекта ключа\n");
        return -1;
    }

    // 2. Генерируем ключевую пару
    //    Внутри:
    //    - генерируется случайный приватный скаляр d
    //    - вычисляется публичная точка Q = d * G
    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        fprintf(stderr, "GENERATE EC KEYPAIR: Ошибка при генерации ключей\n");
        return -1;
    }

    // 3. Дополнительно проверяем корректность ключа
    if (EC_KEY_check_key(key) != 1) {
        EC_KEY_free(key);
        fprintf(stderr, "GENERATE EC KEYPAIR: Ошибка при проверке корректности ключей\n");
        return -1;
    }

    *out_key = key;
    return 0;
}