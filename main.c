#include "bpd.h"

int main(void) {

    /* Génération de clés */

    srand(time(NULL));

    long p = random_prime_number(3,7,5000);
    long q = random_prime_number(3,7,5000);

    while(p==q){
        q = random_prime_number(3,7, 5000);
    }

    long n, s, u;
   
    generate_key_values(p, q, &n, &s, &u);

    /* Pour avoir des clés positives */

    if (u < 0) {
        long t = (p - 1) * (q - 1);
        u = u + t; // On aura toujours (s * u) mod t = 1
    }

    /* Affichage des clés en hexadecimal */

    printf("cle publique = (%lx %lx) \n", s, n);
    printf("cle privee = (%lx, %lx) \n", u, n);
    
    /* Chiffrement */

    char mess[10] = "Hello";
    int len = strlen(mess);
    long * crypted = encrypt(mess, s, n);

    printf("Initial message : %s \n", mess);
    printf("Encoded representation : \n");
    print_long_vector(crypted, len);

    /* Déchiffrement */
    
    char* decoded = decrypt(crypted, len, u, n);
    printf("Decoded : %s\n\n", decoded);

    /* Initialisation de clés */

    Key* pKey = malloc(sizeof(Key));
    Key* sKey = malloc(sizeof(Key));
    init_pair_keys(pKey, sKey, 3, 7);
    printf("pKey : %lx, %lx \n", pKey -> val, pKey -> n);
    printf("sKey : %lx, %lx \n", sKey -> val, sKey -> n);

    char* chaine = key_to_str(pKey);
    printf("key to str : %s \n", chaine);
    Key* k = str_to_key(chaine);
    printf("str to key : %lx, %lx \n", k -> val, k -> n);

    /* Initialisation de signatures */

    Key* pKeyC = malloc(sizeof(Key));
    Key* sKeyC = malloc(sizeof(Key));
    init_pair_keys(pKeyC, sKeyC, 3, 7);

    char* mess2 = key_to_str(pKeyC);
    printf("%s vote pour %s\n", key_to_str(pKey), mess2);
    Signature* sgn = sign(mess2, sKey);
    printf("Signature : ");
    print_long_vector(sgn -> content, sgn -> size);
    chaine = signature_to_str(sgn);
    printf("signature_to_str : %s \n", chaine);
    sgn = str_to_signature(chaine);
    printf("str_to_signature : ");
    print_long_vector(sgn -> content, sgn -> size);

    /* Initialisation de déclarations signées */

    Protected* pr = init_protected(pKey, mess2, sgn);

    if (verify(pr)) {
        printf("Signature valide\n");
    } else {
        printf("Signature non valide\n");
    }
    chaine = protected_to_str(pr);
    printf("protected_to_str : %s\n", chaine);
    pr = str_to_protected(chaine);
    printf("str_to_protected : %s %s %s\n\n", key_to_str(pr -> pKey), pr -> mess, signature_to_str(pr -> sgn));

    free(pKey);
    free(sKey);
    free(pKeyC);
    free(sKeyC);

    /* Vérification de l'installation de la bibliothèque */

    const char * s2 = "Rosetta code" ;
    unsigned char * d2 = SHA256 (s2, strlen (s2), 0) ;

    for (int i = 0; i < SHA256_DIGEST_LENGTH ; i++){
        printf ("%02x", d2[i]);        
    }
    putchar('\n');

    return 0;
}