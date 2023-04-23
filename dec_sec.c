#include "dec_sec.h"

void init_key(Key* key, long val, long n) {
    key -> val = val;
    key -> n = n;
}

void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size) {
    long p = random_prime_number(low_size, up_size, 5000); // Génération d'un p premier aléatoire
    long q = random_prime_number(low_size, up_size, 5000); // Génération d'un q premier aléatoire

    while (p == q) { // On vérifie que p et q soit différents
        q = random_prime_number(low_size, up_size, 5000);
    }

    long n, s, u;

    generate_key_values(p, q, &n, &s, &u); // Génération des clés

    if (u < 0) { // Si u est négatif, on recalcule t et on l'ajoute à u
        long t = (p - 1) * (q - 1);
        u = u + t;
    }

    init_key(pKey, s, n); // Initialisation de la pKey déjà allouée
    init_key(sKey, u, n); // Initialisation de la sKey déjà allouée
}

char* key_to_str(Key* key) {
    char* str = (char*) malloc(sizeof(char) * 5);
    if(str == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }

    sprintf(str, "(%lx,%lx)", key -> val, key -> n); // On écrit sous un format prédéfini les éléments de la clé dans une chaîne de caractères

    return str;
}

Key* str_to_key(char* str) {
    Key* key = (Key*) malloc(sizeof(Key));
    if(key == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    unsigned long val, n;

    sscanf(str, "(%lx,%lx)", &val, &n); // On récupère les informations nécessaires à la génération de la clé

    init_key(key, val, n); // Génération de la clé

    return key;
}

Signature* init_signature(long* content, int size) {
    Signature* sgn = (Signature*) malloc(sizeof(Signature));
    if(sgn == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    sgn -> content = content;
    sgn -> size = size;

    return sgn;
}

Signature* sign(char* mess, Key* sKey) {
    Signature* sgn = init_signature(encrypt(mess, sKey -> val, sKey -> n), strlen(mess));
    // On crypte le message et on initialise la signature

    return sgn;
}

char* signature_to_str(Signature* sgn) {
    char* result = malloc(10 * sgn -> size * sizeof(char));
    if(result == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    result[0] = '#'; // La signature commence systématiquement par un #
    int pos = 1;
    char buffer[156];

    for (int i = 0; i < sgn -> size; i++) { // On parcourt les éléments de la signature
        sprintf(buffer, "%lx", sgn -> content[i]); // On écrit chaque élément de la signature dans une chaîne de caractères
        for (int j = 0; j < strlen(buffer); j++) { // On parcourt les éléments du buffer
            result[pos] = buffer[j]; // On met l'élément j du buffer dans la case pos du result
            pos = pos + 1;
        }
        result[pos] = '#'; // Chaque case de result commence systématquemnt par un #
        pos = pos + 1;
    }
    result[pos] = '\0';
    result = realloc(result, (pos + 1) * sizeof(char)); // On alloue une nouvelle case à result

    return result;
}

Signature* str_to_signature(char* str) {
    int len = strlen(str);
    long* content = (long*) malloc(sizeof(long) * len);
    if(content == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    int num = 0;
    char buffer[256];
    int pos = 0;

    for (int i = 0; i < len; i++) {
        if (str[i] != '#') { // On ajoute chaque élément différent de # au buffer
            buffer[pos] = str[i];
            pos = pos + 1;
        } else { // On ajoute l'élément suivant
            if (pos != 0) {
                buffer[pos] = '\0';
                sscanf(buffer, "%lx", &(content[num]));
                num = num + 1;
                pos = 0;
            }
        }
    }
    content = realloc(content, num * sizeof(long)); // On alloue de la place supplément au content

    return init_signature(content, num);
}

Protected* init_protected(Key* pKey, char* mess, Signature* sgn) {
    Protected* pr = (Protected*) malloc(sizeof(Protected));
    if(pr == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    pr -> pKey = pKey;

    pr -> mess = strdup(mess);

    pr -> sgn = sgn;

    return pr;
}

int verify(Protected* pr) {
    char* decrypt_str = decrypt(pr -> sgn -> content, pr -> sgn -> size, pr -> pKey -> val, pr -> pKey -> n);
    
    if (strcmp(decrypt_str, pr -> mess) == 0) { // Si la chaine décryptée correspond au message, la signature est validée
        free(decrypt_str);
        return 1;
    }
    
    free(decrypt_str);
    return 0;
}

char* protected_to_str(Protected* pr) {
    char* str = (char*) malloc(sizeof(char) * 256);
    if(str == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    char* key_str = key_to_str(pr -> pKey);
    char* sgn_str = signature_to_str(pr -> sgn);
    sprintf(str, "%s %s %s", key_str, pr -> mess, sgn_str); // On écrit sous un format prédéfini les éléments de la déclaration dans une chaîne de caractères
    free(sgn_str);
    free(key_str);

    return str;
}

Protected* str_to_protected(char* str) {
    char* pKey_str = (char*) malloc(sizeof(char) * strlen(str));
    char* mess_str = (char*) malloc(sizeof(char) * strlen(str));
    char* sgn_str = (char*) malloc(sizeof(char) * strlen(str));
    
    if(pKey_str == NULL || mess_str == NULL  || sgn_str == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }

    sscanf(str, "%s %s %s", pKey_str, mess_str, sgn_str); // On récupère les informations
    Protected* pr = init_protected(str_to_key(pKey_str), mess_str, str_to_signature(sgn_str)); // INitialisation d'une déclaration
    free(pKey_str); free(mess_str); free(sgn_str);

    return pr;
}

void generate_random_data(int nv, int nc) {
    FILE* keys = fopen("./RandomDatas/keys.txt", "w"); // Fichier avec les clés (publiques et privées) des citoyens

    if (keys == NULL) { printf("Erreur lors de l'ouverture du ficher\n"); return; }

    Key** pKeys = (Key**) malloc(sizeof(Key*) * nv); // Tableau avec les clés publiques des citoyens
    Key** sKeys = (Key**) malloc(sizeof(Key*) * nv); // Tableau avec les clés privées des citoyens

    if(pKeys == NULL || sKeys == NULL){
        printf("Erreur à l'allocation\n");
        return;
    }

    for (int i = 0; i < nv; i++) {
        pKeys[i] = (Key*) malloc(sizeof(Key));
        sKeys[i] = (Key*) malloc(sizeof(Key));
        if(pKeys[i] == NULL || sKeys[i] == NULL){
            printf("Erreur à l'allocation\n");
            return;
        }
        init_pair_keys(pKeys[i], sKeys[i], 3, 7);

        char* pKey_str = key_to_str(pKeys[i]);
        char* sKey_str = key_to_str(sKeys[i]);
        fprintf(keys, "%s %s\n", pKey_str, sKey_str);

        free(pKey_str); free(sKey_str);

    }

    Key** candKeys = (Key**) malloc(sizeof(Key*) * nc); // Tableau avec les clés publiques des candidats
    if(candKeys == NULL){
        printf("Erreur à l'allocation\n");
        return;
    }

    for(int i = 0; i < nc ; i++){
        candKeys[i] = NULL;
    }

    int* valX = (int*) malloc(sizeof(int) * nc); // Tableau avec l'indice des cases déjà parcourues
    if(valX == NULL){
        printf("Erreur à l'allocation\n");
        return;
    }
    valX[0] = rand()%nv;
    candKeys[0] = pKeys[valX[0]];

    for (int i = 1; i < nc; i++) {
        int x = rand()%nv;

        for (int j = 0; j < nc; j++) {
            if (x == valX[j]) {
                x = rand()%nv;
            }
        }
        valX[i] = x;

        candKeys[i] = pKeys[x];
    }

    FILE* candidates = fopen("./RandomDatas/candidates.txt", "w"); // Fichier avec les clés publiques des candidats
    if (candidates == NULL) { printf("Erreur lors de l'ouverture du fichier\n"); return;}

    for (int i = 0; i < nc; i++) {
        char* candKey_str = key_to_str(candKeys[i]);
        fprintf(candidates, "%s\n", candKey_str);
        free(candKey_str);
    }

    FILE* declarations = fopen("./RandomDatas/declarations.txt", "w"); // Fichier avec les déclarations signées
    if (declarations == NULL) { printf("Erreur lors de l'ouverture du fichier\n"); return;}

    char* mess; Signature* sgn; Protected* pr; char* pr_str;

    for (int i = 0; i < nv; i++) {
        mess = key_to_str(candKeys[rand()%nc]);
        sgn = sign(mess, sKeys[i]);
        pr = init_protected(pKeys[i], mess, sgn);
        pr_str = protected_to_str(pr);

        fprintf(declarations, "%s\n", pr_str);

        free(mess);
        free(sgn->content);
        free(sgn);
        free(pr->mess);
        free(pr);
        free(pr_str);

    }

    // LIBERATION DE LA MEMOIRE

    for(int i = 0; i < nv; i++){
      free(pKeys[i]);
      free(sKeys[i]);
    }

    free(pKeys);
    free(sKeys);
    free(candKeys);
    free(valX);
    fclose(keys);
    fclose(candidates);
    fclose(declarations);

}
