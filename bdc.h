#ifndef BDC_H
#define BDC_H

#include "dec_sec.h"

/* Structures */

typedef struct cellKey {
    Key* data; // Pointeur sur la clé
    struct cellKey* next; // Pointeur sur l'élément suivant
} CellKey; // Nom de la structure : CellKey

typedef struct cellProtected {
    Protected* data; // Pointeur sur le 1er élément
    struct cellProtected* next; // Pointeur sur l'élément suivant
} CellProtected; // Nom de la structure : CellProtected

typedef struct hashCell {
    Key* key; // Pointeur sur la clé
    int val; 
    // Si candidat : nombre de votes en sa faveur
    // Si votant : 1 si il a voté et 0 sinon
} HashCell; // Nom de la structure : HashCell

typedef struct hashTable {
    HashCell** tab; // Table de hachage
    int size; // Taille de la table de hachage
} HashTable; // Nom de la structure : HashTable

/* Prototypes */

CellKey* create_cell_key(Key* key); // initialise la liste chaînée de clés
void add_key(CellKey** LCK, Key* key); // ajoute une clé, en tête de la liste chaînée en paramètres
CellKey* read_public_keys(char* nomfic); // retourne une liste chaînée de clés générée à partir du fichier en paramètres
void print_list_keys(CellKey* LCK); // affiche la liste de clés en paramètres
void delete_cell_key(CellKey* c); // supprime un élément d'une liste chaînée de clés
void delete_list_keys(CellKey* LCK); // supprime une liste chaînée de clés

CellProtected* create_cell_protected(Protected* pr); // initialise la liste chaînée de déclarations signées
void add_protected(CellProtected** LCP, Protected* pr); // ajoute une déclaration signées, en tête de la liste chaînée en paramètres
CellProtected* read_protected(char* nomfic); // retourne une liste chaînée de déclarations signées générée à partir du fichier en paramètres
void print_list_protected(CellProtected* LCP); // affiche la liste de déclarations signées en paramètres
void delete_cell_protected(CellProtected* c); // supprime un élément d'une liste chaînée de déclarations signées
void delete_list_protected(CellProtected* LCP); // supprime une liste chaînée de déclarations signées

void anti_fraude(CellProtected** LCP); // supprime toutes les déclarations dont la signature n'a pas été validée

HashCell* create_hashcell(Key* key); // alloue une cellule de la table de hachage et initialise ses champs
int hash_function(Key* key, int size); // retourne la position d'un élément dans la table de hachage
int find_position(HashTable* t, Key* key); // cherche dans la table s'il existe un élément dont la clé est key et retourne sa position, sinon il retourne une position où l'on peut le placer
HashTable* create_hashtable(CellKey* keys, int size); // initialise une table de hachage qui contient une cellule pour chaque clé de la liste chaînée
void delete_hashtable(HashTable* t); // supprime une table de hachage
void affiche_hashtable(HashTable* h); // affiche la table de hachage
Key* compute_winner(CellProtected* decl, CellKey* candidates, CellKey* voters, int sizeC, int sizeV); // calcule le vainqueur de l'élection

int equal_keys(HashCell* cell, Key* key); // retourne 1 si les deux clés sont égales et 0 sinon

#endif