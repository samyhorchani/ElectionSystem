#ifndef DEC_SEC_H
#define DEC_SEC_H

#include "dev_out_crypto.h"

/* Structures */

typedef struct key {
    long val; // Premier élément du couple
    long n; // Deuxième élément du couple
} Key; // Nom de la structure : Key

typedef struct signature {
    long* content; // Contenu de la signature (tableau de long)
    int size; // Taille du tableau
} Signature; // Nom de la structure : Signature

typedef struct protected {
    Key* pKey; // Clé publique de l'émetteur
    char* mess; // Message
    Signature* sgn; // Signature
} Protected; // Nom de la structure : Protected

/* Prototypes */

void init_key(Key* key, long val, long n); // initialise la clé
void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size); // initialise pKey et sKey
char* key_to_str(Key* key); // retourne la chaîne de caractères associée à la clé
Key* str_to_key(char* str); // retourne la clé associée à la chaîne de caractères

Signature* init_signature(long* content, int size); // initialise la signature
Signature* sign(char* mess, Key* sKey); // retourne la signature associée à sKey et mess
char* signature_to_str(Signature* sgn); // retourne la chaîne de caractères associée à la signature
Signature* str_to_signature(char* str); // retourne la signature associée à la chaîne de caractères

Protected* init_protected(Key* pKey, char* mess, Signature* sgn); // initialise la déclaration signée
int verify(Protected* pr); // retourne 1 si la signature correspond au message et à la personne de la déclaration et 0 sinon
char* protected_to_str(Protected* pr); // retourne la chaîne de caractères associée à la déclaration signée
Protected* str_to_protected(char* str); // retourne la déclaration signée associée à la chaîne de caractères

void generate_random_data(int nv, int nc); // crée des fichiers .txt pour les couples de clés, les clés publiques, les déclarations (on suppose que nv >= nc)

#endif