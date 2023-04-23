#include "bdc.h"

CellKey* create_cell_key(Key* key) {
    CellKey* LCK = (CellKey*) malloc(sizeof(CellKey));
    if(LCK == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }

    LCK -> data = key;
    LCK -> next = NULL;

    return LCK;
}

void add_key(CellKey** LCK, Key* key) {
    if(*LCK == NULL){ // Si LCK "n'existe pas", on la crée
        *LCK = create_cell_key(key);
        return;
    }

    CellKey* newLCK = create_cell_key(key); // Création du nouvelle cellule pour la clé
    newLCK->next = *LCK; // Permet de ne pas "perdre" les éléments suivants
    *LCK = newLCK; // Ajout de la cellule à la position suivante dans LCK
}


CellKey* read_public_keys(char* nomfic){
    FILE* file = fopen(nomfic, "r");

    if (file == NULL){
        printf("Erreur lors de l'ouverture du fichier\n");
        return NULL;
    }

    CellKey* LCK = NULL; //pour que derniere case = NULL
    char ligne[256];
    char key_str[50];
    Key* pKey = NULL;
    while(fgets(ligne, 256, file) != NULL){
        if(sscanf(ligne, "%s", key_str)==1){ //prise en compte que de la 1ere clé == pKey
            pKey = str_to_key(key_str);
            add_key(&LCK, pKey);
        }else{
            printf("Format de ligne incorrect");
            fclose(file);
            return NULL;
        }
    }

    fclose(file);
    return LCK;
}

void print_list_keys(CellKey* LCK){
    
    if(LCK == NULL){
        printf("Liste de clés vide\n");
        return;
    }
    int i = 0;
    while(LCK){ // On parcourt LCK et on affiche chaque clé
        printf("(%lx, %lx)\n", LCK->data->val, LCK->data->n);
        LCK = LCK -> next;
        i++;
    }
    printf("Taille de la liste : %d\n", i);
}

void delete_cell_key(CellKey* c){
    free(c->data);
    free(c);
}

void delete_list_keys(CellKey* LCK){
    if(LCK == NULL){ // Si LCK "n'existe pas", on ne fait rien
        return;
    }
    while (LCK){ // On parcourt chaque élément de LCK et on les supprime un par un
        CellKey* tmp = LCK->next; // Permet de ne pas "perdre" les éléments suivants
        delete_cell_key(LCK);
        LCK = tmp;
    }
}


CellProtected* create_cell_protected(Protected* pr){
    CellProtected* LCP = (CellProtected*) malloc(sizeof(CellProtected));
    
    if(LCP==NULL){ // Si LCP "n'exite pas", il y a un problème à l'allocation
        printf("Erreur à l'allocation\n");
        return NULL;
    }

    LCP -> data = pr;
    LCP -> next = NULL;

    return LCP;
}

void add_protected(CellProtected** LCP, Protected* pr){
    if(*LCP == NULL){ // Si LCP "n'existe pas", on la crée
        *LCP = create_cell_protected(pr);
        return;
    }

    CellProtected *newLCP = create_cell_protected(pr); // Création du cellule pour la déclaration 
    newLCP->next = *LCP; // Permet de ne pas "perdre" les éléments suivants
    *LCP = newLCP; // Ajout de la cellule à la position suivante dans LCP
}

CellProtected* read_protected(char* nomfic){
    FILE* file = fopen(nomfic, "r");
    if(file == NULL){ // Si file "n'exite pas", il y a un problème à l'ouverture en lecture du fichier
        printf("Erreur à l'ouverture du fichier\n");
        return NULL;
    }

    char ligne[256];
    Protected* pr = NULL;
    CellProtected* LCP = NULL;
    while(fgets(ligne, 256, file) != NULL){ // On récupère chaque ligne du fichier et on mets les éléments (de la chaîne formatée) dans LCP
        pr = str_to_protected(ligne);
        add_protected(&LCP, pr);
    }

    fclose(file);
    return LCP;
}

void print_list_protected(CellProtected* LCP){
    if(LCP == NULL){
        printf("Liste de déclarations vide\n");
        return;
    }
    int i = 0;
    while(LCP){ // On parcourt LCP et on afficher chaque élément
        char* pr_str = protected_to_str(LCP->data);
        printf("%s\n", pr_str);
        LCP = LCP -> next;
        free(pr_str);
        i++;
    }
    printf("Taille de la liste : %d\n", i);
}

void delete_cell_protected(CellProtected* c){
    if(c){
        Protected* pr_aSupprimer = c->data;
        Signature* sgn_aSupprimer = pr_aSupprimer -> sgn;
        free(sgn_aSupprimer->content); //liberation du contenu de la signature
        free(sgn_aSupprimer);
        free(pr_aSupprimer->mess); //liberation du message contenu dans protected
        free(pr_aSupprimer->pKey); //liberation pKey contenue dans pr

        free(pr_aSupprimer); //liberation de pr
        free(c);
    }

}

void delete_list_protected(CellProtected* LCP){
    if(LCP == NULL){ // Si LCP "n'existe pas", on ne fait rien
        return;
    }
    CellProtected* tmp = NULL; 

    while (LCP){ // On parcourt chaque élément de LCK et on les supprime un par un
        tmp = LCP->next; // Permet de ne pas "perdre" les éléments suivants
        delete_cell_protected(LCP);
        LCP = tmp;
    }

}

void anti_fraude(CellProtected** LCP){
  CellProtected* tmp = *LCP; // Parcours plus simple de la liste
  CellProtected* prec = NULL;
  CellProtected* aSupprimer = NULL;

  while(tmp){ // On parcourt chaque élément de tmp

    if(verify(tmp->data) != 1){ // La déclaration n'est pas vérifiée
      if(prec){ // Si prec "existe"
           prec->next = tmp->next; // On "écrase" l'élément courant
      }else{
          *LCP = (*LCP)->next; // On passe à l'élément suivant
      }

      aSupprimer = tmp;
      tmp = tmp->next; // Passage à l'élément suivant
      delete_cell_protected(aSupprimer); // On supprime la déclaration non vérifiée
    }
    else{
      prec = tmp;
      tmp = tmp->next; // Passage à l'élément suivant
    }
  }
}

HashCell* create_hashcell(Key* key) {
    HashCell* hc = (HashCell*) malloc(sizeof(HashCell));
    if(hc == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    hc -> key = key;
    hc -> val = 0; // On initialise à 0 automatiquement (utile pour compter le nb de voix)

    return hc;
}

int hash_function(Key* key, int size) {
    long cle = key -> val * key -> n;

    return (int)(cle % size); // Position de la clé dans la table
}

int find_position(HashTable* t, Key* key) {

    if (t && key) { // Si la clé et la table existe
        int hash = hash_function(key, t -> size); // Position prévue pour la clé
        
        for (int i = 0; i < t -> size; i++) { // On parcourt la table de hachage
            int pos = (hash + i) % (t -> size); // On calcule la nouvelle position

            if (equal_keys(t -> tab[pos], key) == 1) { // Si la clé est trouvée
                return pos; // On renvoie la position
            }
        }

        return hash;
    }

    return -1;
}

int equal_keys(HashCell* cell, Key* key) {
    if (cell && key) {
        if (cell -> key -> val == key -> val && cell -> key -> n == key -> n) {
            return 1;
        }
    }
    return 0;
}

HashTable* create_hashtable(CellKey* keys, int size) {

    if (keys) { // Si la liste de clés existe
        HashTable* ht = (HashTable*) malloc(sizeof(HashTable));
        if(ht == NULL){
            printf("Erreur à l'allocation\n");
            return NULL;
        }
        ht -> tab = (HashCell**) malloc(sizeof(HashCell*) * size);
        if(ht->tab == NULL){
            printf("Erreur à l'allocation\n");
            free(ht);
            return NULL;
        }
        ht -> size = size;

        for (int i = 0; i < size; i++) { // On parcourt la table
            ht -> tab[i] = NULL; // On initialise toutes les cases à NULL
        }

        while (keys) { // On parcourt la liste
            int hash = find_position(ht, keys -> data); // On cherche une position pour la clé

            if (ht -> tab[hash] == NULL) { // Si la case est vide
                ht -> tab[hash] = create_hashcell(keys -> data); // On attribue la place à la clé
            }
            if (equal_keys(ht -> tab[hash], keys -> data) == 0) { // Si deux clés à la même position sont différentes
                for (int i = 0; i < ht -> size; i++) { // On parcourt la table de hachage
                    int pos = (hash + i) % (ht -> size); // On calcule la nouvelle position

                    if (ht -> tab[pos] == NULL) { // Si la case est vide
                        ht -> tab[pos] = create_hashcell(keys -> data); // On attribue la place à la clé
                        break; // On sort de la boucle
                    }
                }
            }

            keys = keys -> next;
        } 
        return ht; // On renvoie la table créée
    }
    
    return NULL;
}

void delete_hashtable(HashTable* t) {
    for(int i = 0; i < t -> size; i++){ // On parcourt les éléments de la table
        free(t-> tab[i] -> key); // On libère la clé
        free(t -> tab[i]); // On libère la case
    }

    free(t -> tab); // On libère le tableau
    free(t); // On libère la table
}

void affiche_hashtable(HashTable* h) {

    if (h) {
        printf("Affichage de la table de hachage :\n");

        for(int i = 0; i < h->size ; i++){
            if(h -> tab[i]){
                char* key = key_to_str(h->tab[i]->key);
                printf("%s\n", key);
                free(key);
            }
        }

        printf("Fin Affichage de la table de hachage.\n");
    } else {
        printf("Impossible d'afficher la table !\n");
    }
}

Key* compute_winner(CellProtected* decl, CellKey* candidates, CellKey* voters, int sizeC, int sizeV) {
    HashTable* cand_tab = create_hashtable(candidates, sizeC); // Table de hachage pour les candidats
    HashTable* vot_tab = create_hashtable(voters, sizeV); // Table de hachage pour les votants
    
    anti_fraude(&decl); // On retire toutes les fraudes

    while (decl){
        int posV = find_position(vot_tab, decl -> data -> pKey); // On cherche la position du votant dans Hv

        if (equal_keys(vot_tab -> tab[posV], decl -> data -> pKey) == 1) { // On vérifie que le votant est bien dans Hv
            Key* mess = str_to_key(decl -> data -> mess); // On récupère le vote du candidat
            int posC = find_position(cand_tab, mess); // On cherche la position du candidat dans Hc

            if (vot_tab -> tab[posV] -> val == 0) { // S'il n'a pas voté

                if (equal_keys(cand_tab -> tab[posC], mess) == 1) { // S'il est présent
                    cand_tab -> tab[posC] -> val += 1; // On ajoute une voix
                    vot_tab -> tab[posV] -> val = 1; // On indique que le votant a voté
                }

            }
            free(mess); // il était dans le if au dessus
        }

        decl = decl -> next;
    }

    int maxVoix = 0; Key* gagnant;
    int total = 0;
    for (int i = 0; i < sizeC; i++) {
        if (cand_tab -> tab[i] != NULL) {
            char* tmp_key = key_to_str(cand_tab -> tab[i]->key);
            printf(" - Le candidat %s a obtenu %d votes\n",tmp_key, cand_tab -> tab[i]->val);
            free(tmp_key);
            total+= cand_tab -> tab[i]->val;
            if(cand_tab -> tab[i] -> val >= maxVoix){
                maxVoix = cand_tab -> tab[i] -> val;
                gagnant = cand_tab -> tab[i] -> key;
            }
            
        }
    }

    char* gagnant_str = key_to_str(gagnant);
    printf("Nous avons enregistré %d de votes \n", total);
    printf("\nLe gagnant de l'élection est %s !\n\n", gagnant_str);
    free(gagnant_str);

    for(int i = 0 ; i < sizeC; i++){
        free(cand_tab->tab[i]);
    }
    free(cand_tab->tab);
    free(cand_tab);
    for(int i = 0 ; i < sizeV; i++){
        free(vot_tab->tab[i]);
    }
    free(vot_tab->tab);
    free(vot_tab);


    return gagnant;
}