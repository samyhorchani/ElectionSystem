#ifndef BPD_H
#define BPD_H

#include "bdc.h"
#include <openssl/sha.h>
#include <dirent.h>


/* Structures */

typedef struct block {
    Key* author; // Clé publique du créateur
    CellProtected* votes; // Liste de déclarations de vote
    unsigned char* hash; // Valeur hachée du bloc
    unsigned char* previous_hash; // Valeur hachée du bloc précédent
    int nonce; // Preuve de travail
} Block; // Nom de la structure : Block

typedef struct block_tree_cell {
    Block* block ;
    struct block_tree_cell* father ;
    struct block_tree_cell* firstChild ;
    struct block_tree_cell* nextBro ;
    int height ;
} CellTree ; // Nom de la structure : CellTree

/* Prototypes */

void write_block(char* nomfic,Block*b); // écrit un bloc dans un fichier
Block* read_block(char* nomfic); // crée un bloc à partir d'un fichier
char* block_to_str(Block* B); // génère une chaîne de caractères représentant un bloc
unsigned char* hash_function_SHA256(const char* s); // retourne la valeur hachée obtenue par l'algorithme SHA256
void compute_proof_of_work(Block *B, int d); // rend un bloc valide (en initialisant et complétant la preuve de travail)
int verify_block(Block* b, int d); // vérifie la validité du bloc
void delete_block(Block* b); // supprime un bloc

int verify_zeros(unsigned char* hash,int d); // vérifie le nombre de zéros de hash
char* hash_to_str(unsigned char * hash); // retourne la chaîne de caractères associée au hash
unsigned char * str_to_hash(char* st); // retourne le hash associée à la chaîne de caractères

CellTree* create_node(Block* b); // crée et initialise un noeud
int update_height(CellTree* father, CellTree* child); // MÀJ de la hauteur du noeud father (renvoie 1 si MÀJ effectuée et 0 sinon)
void add_child(CellTree* father, CellTree* child); // ajoute un fils à un noeud
void print_tree(CellTree* ab); // affiche un arbre
void delete_node(CellTree* node); // supprime un noeud d'un arbre
void delete_tree(CellTree* ab); // supprime un arbre
CellTree* highest_child(CellTree* cell); // renvoie le noeud fils avec la plus grande hauteur
CellTree* last_node(CellTree* tree); // retourne la valeur hachée du dernier bloc
CellProtected* fusion_list_protected(CellProtected* l1, CellProtected* l2); // fusionne deux listes chaînées de déclarations signées
CellProtected* fusion_votes(CellTree* tree); // fusionne les listes chaînées de déclarations contenues dans les blocs de la plus longue chaîne

void submit_vote(Protected* p); // permet à un citoyen de soumettre un vote et de l'ajouter à la fin d'un fichier
void create_block(CellTree* tree, Key* author, int d); // crée un bloc et initialise des valeurs
void add_block(int d, char* name); // crée un fichier représentant le bloc et l'ajoute dans un répertoire
CellTree* read_tree(); // retourne la racine de l'arbre
Key* compute_winner_BT(CellTree* tree, CellKey* candidates, CellKey* voters, int sizeC, int sizeV); // détermine le gagnant de l'élection en se basant sur la plus longue chaine de l'arbre

#endif