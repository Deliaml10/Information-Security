#include <stdio.h>
#include <stdlib.h>
#include <string.h> 

const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/";

void encryption(char *input, char *key){
    int inputlen = strlen(input);
    int keylen = strlen(key);
    int alphabetlen = strlen(alphabet);

    char *encrypted = malloc((inputlen + 1) * sizeof(char));
    if (encrypted == NULL) {
        printf("Error.\n");
        return;
    }

    
    for (int i = 0, j = 0; i < inputlen; i++) {
        char c = input[i];
        char *pos = strchr(alphabet, c);
        if (pos) {
            int index = pos - alphabet;
            int key_index = strchr(alphabet, key[j % keylen]) - alphabet;
            c = alphabet[(index + key_index) % alphabetlen];
            j++;
        }
        encrypted[i] = c;
    }

    
    encrypted[inputlen] = '\0';
    printf("Encrypted text: %s\n", encrypted);

    free(encrypted);
}

void decryption(char *encrypted, char *key){
    int inputlen = strlen(encrypted);
    int keylen = strlen(key);
    int alphabetlen = strlen(alphabet);

    char *decrypted = malloc((inputlen + 1) * sizeof(char));
    if (decrypted == NULL) {
        printf("Error.\n");
        return;
    }

    
    for (int i = 0, j = 0; i < inputlen; i++) {
        char c = encrypted[i];
        char *pos = strchr(alphabet, c);
        if (pos) {
            int index = pos - alphabet;
            int key_index = strchr(alphabet, key[j % keylen]) - alphabet;
            c = alphabet[(index - key_index + alphabetlen) % alphabetlen];
            j++;
        }
        decrypted[i] = c;
    }

    
    decrypted[inputlen] = '\0';
    printf("Decrypted text: %s\n", decrypted);

    free(decrypted);
}

int main(){

    char input[256];
    char key[256];
    char key2[256];
    char encrypt[256];

    printf("Enter the input string: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';

    printf("Enter the key for encrypt: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';

    encryption(input, key);

    printf("Enter the encrypted text to decrypt: ");
    fgets(encrypt, sizeof(encrypt), stdin);
    encrypt[strcspn(encrypt, "\n")] = '\0';

    printf("Enter the key for decrypt: ");
    fgets(key2, sizeof(key2), stdin);
    key2[strcspn(key2, "\n")] = '\0';

    decryption(encrypt, key2);

    return 0;
}