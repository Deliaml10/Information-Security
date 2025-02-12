#include <stdio.h>
#include <stdlib.h>
#include <string.h> 

void encryption(char *input, char *key){
    int inputlen = strlen(input);
    int keylen = strlen(key);

    char *encrypted = malloc((inputlen + 1) * sizeof(char));
    if (encrypted == NULL) {
        printf("Error.\n");
        return;
    }

//Algorithm for encryption using Veginere cipher    
for (int i = 0; i < inputlen; i++) {
    if (input[i] >= 32 && input[i] <= 126) {
        int key_index = (key[i % keylen] - 32);
        encrypted[i] = 32 + ((input[i] - 32 + key_index) % 95);
    } else {
        encrypted[i] = input[i]; 
    }
}

    encrypted[inputlen] = '\0';
    printf("Encrypted text: %s\n", encrypted);

    free(encrypted);
}

void decryption(char *encrypted, char *key){
    int inputlen = strlen(encrypted);
    int keylen = strlen(key);

    char *decrypted = malloc((inputlen + 1) * sizeof(char));
    if (decrypted == NULL) {
        printf("Error.\n");
        return;
    }

// Algorithm for decryption using the opposite Veginere cipher
for (int i = 0; i < inputlen; i++) {
    if (encrypted[i] >= 32 && encrypted[i] <= 126) { 
        int key_index = (key[i % keylen] - 32);
        decrypted[i] = 32 + ((encrypted[i] - 32 - key_index + 95) % 95);
    } else {
        decrypted[i] = encrypted[i]; 
    }
}
 
    decrypted[inputlen] = '\0';
    printf("Decrypted text: %s\n", decrypted);

    free(decrypted);
}

int main(){

    char input[256];
    char key[256];
    char encrypt[256];
    char key2[256];

//User input the text to encrypt and the key
    printf("Enter the input string: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';

    printf("Enter the key for encrypt: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';

//Function for encryption
    encryption(input, key);

//User input the text to decrypt and the key
    printf("Enter the encrypted text to decrypt: ");
    fgets(encrypt, sizeof(encrypt), stdin);
    encrypt[strcspn(encrypt, "\n")] = '\0';

    printf("Enter the key for decrypt: ");
    fgets(key2, sizeof(key2), stdin);
    key2[strcspn(key2, "\n")] = '\0';

//Function for decryption
    decryption(encrypt, key2);

    return 0;
}
