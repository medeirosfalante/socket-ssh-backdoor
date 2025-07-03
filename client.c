#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char *base64_encode(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';
    BIO_free_all(b64);
    return buff;
}

SSL_CTX *init_client_ctx()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Erro ao criar contexto SSL");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main()
{
    int sock;
    struct sockaddr_in server_addr;
    char message[1024];

    SSL_CTX *ctx = init_client_ctx();
    SSL *ssl = SSL_new(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    while (1)
    {
        printf("Escreva a mensagem: ");
        if (!fgets(message, sizeof(message), stdin)) {
            printf("Erro ao ler mensagem\n");
            break;
        }

        message[strcspn(message, "\n")] = '\0';
        if (strcmp(message, "exit") == 0)
            break;

        unsigned char aes_key[32], aes_iv[16];
        if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 || RAND_bytes(aes_iv, sizeof(aes_iv)) != 1)
        {
            fprintf(stderr, "Erro ao gerar AES key/IV\n");
            continue;
        }

        EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
        unsigned char ciphertext[1024];
        int len, ciphertext_len;

        EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_EncryptUpdate(ctx_enc, ciphertext, &len, (unsigned char *)message, strlen(message));
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx_enc, ciphertext + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx_enc);

        char *payload_b64 = base64_encode(ciphertext, ciphertext_len);

        FILE *pubkey_file = fopen("public.pem", "r");
        if (!pubkey_file)
        {
            perror("Erro ao abrir public.pem");
            free(payload_b64);
            break;
        }

        RSA *rsa_pub = PEM_read_RSA_PUBKEY(pubkey_file, NULL, NULL, NULL);
        fclose(pubkey_file);
        if (!rsa_pub)
        {
            perror("Erro ao carregar chave pública");
            free(payload_b64);
            break;
        }

        unsigned char key_iv[48];
        memcpy(key_iv, aes_key, 32);
        memcpy(key_iv + 32, aes_iv, 16);

        unsigned char encrypted_key_iv[256];
        int encrypted_len = RSA_public_encrypt(sizeof(key_iv), key_iv, encrypted_key_iv, rsa_pub, RSA_PKCS1_OAEP_PADDING);
        RSA_free(rsa_pub);

        if (encrypted_len == -1)
        {
            fprintf(stderr, "Erro ao criptografar chave com RSA\n");
            free(payload_b64);
            continue;
        }

        char *keyblob_b64 = base64_encode(encrypted_key_iv, encrypted_len);

        char json[4096];
        snprintf(json, sizeof(json),
                 "{\n  \"keyblob\": \"%s\",\n  \"payload\": \"%s\"\n}\n",
                 keyblob_b64, payload_b64);

        SSL_write(ssl, json, strlen(json));

        char response[2048] = {0};
        int bytes = SSL_read(ssl, response, sizeof(response) - 1);
        if (bytes > 0)
        {
            response[bytes] = '\0';
            printf("Resposta do servidor:\n%s\n", response);
        }

        free(payload_b64);
        free(keyblob_b64);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
