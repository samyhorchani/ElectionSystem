#include "bpd.h"

void write_block(char* nomfic, Block* b) {
    FILE* fichier = fopen(nomfic,"w"); // Ouverture du fichier

    if(fichier == NULL){
        printf("Erreur à l'ouverture du fichier !\n");
        return;
    }

    // On récupère les éléments du bloc

    char* cle = key_to_str(b -> author);
    char* hash = hash_to_str(b -> hash);
    char* prev = hash_to_str(b -> previous_hash);
    int nonce = b -> nonce;

    // On écrit les éléments du bloc dans le fichier

    fprintf(fichier,"%s\n", cle);
    fprintf(fichier,"%s\n%s\n%d\n", hash, prev, nonce);

    // On récupère les déclarations de vote

    CellProtected* votes = b -> votes;
    while(votes){
        char* decl = protected_to_str(votes -> data);
        fprintf(fichier, "%s\n", decl); // On écrit la déclaration de vote dans le fichier
        votes = votes -> next;
        free(decl);
    }

    fprintf(fichier,"~"); // Ajout systématique à la fin du bloc

    free(cle); free(hash); free(prev); // Libération de la mémoire

    fclose(fichier); // Fermeture du fichier
}

Block* read_block(char* nomfic){
    FILE* fichier = fopen(nomfic, "r"); // Ouverture du fichier

    if (fichier == NULL){
        printf("Erreur d'ouverture du fichier !\n");
        return NULL;
    }

    Block* bloc = (Block*) malloc(sizeof(Block)); // Allocation de la mémoire

    if (bloc == NULL) {
        printf("Erreur d'allocation ! \n");

        return NULL;
    }

    // On parcourt les lignes du fichier

    char ligne[256];
    fgets(ligne, 256, fichier);

    // On récupère la clé
    
    char cle_str[256];

    if (sscanf(ligne,"%s",cle_str)!=1) {
        printf("Erreur de lecture de la clé\n");

        free(bloc);

        return NULL;
    }

    bloc -> author = str_to_key(cle_str);

    // On récupère la valeur hachée du bloc et du bloc précédent

    char hash_str[256];
    char prev_str[256];

    fgets(hash_str, 256, fichier); 
    fgets(prev_str, 256, fichier);

    unsigned char* hash = str_to_hash(hash_str);
    unsigned char* prev = str_to_hash(prev_str);


    if(hash == NULL || prev == NULL){
        printf("Erreur de lecture des valeurs de hachage !\n");

        free(bloc);
        free(prev);
        free(hash);

        return NULL;
    }

    bloc -> hash = hash;
    bloc -> previous_hash = prev;

    // On récupère la preuve de travail

    fgets(ligne, 256, fichier);

    int nonce;

    if(sscanf(ligne, "%d", &nonce) != 1){
        printf("Erreur de lecture de la preuve de travail !\n");

        free(bloc);

        return NULL;
    }

    bloc -> nonce = nonce;

    // On récupère les déclarations de vote 

    fgets(ligne, 256, fichier);
    
    CellProtected* tete = NULL;
    CellProtected* last = NULL;

    while (strcmp(ligne, "~") != 0){

        Protected* pr = str_to_protected(ligne);  

        if (pr == NULL){
            printf("Les prochaines lignes ne seront pas prises en compte\n");

            return bloc;
        }

        if (tete == NULL){
            tete = create_cell_protected(pr);
            last = tete;
        } else {

            last -> next = create_cell_protected(pr);
            last = last->next;
        }

        fgets(ligne, 256, fichier);
    }

    bloc -> votes = tete;

    fclose(fichier); // Fermeture du fichier

    return bloc;
}

char* block_to_str(Block* B){

    // On détermine la taille de la chaîne de caractères

    int taille = 0;

    // Taille de la clé
    char* cle = key_to_str(B -> author);
    taille += strlen(cle);

    // Taille de la valeur hachée du bloc précédent
    char* previous = hash_to_str(B -> previous_hash);
    taille += strlen(previous);

    // Taille de la liste de déclarations de vote
    CellProtected* courant = B->votes;

    int nb_votes = 0;

    CellProtected* votes = B -> votes;

    while (votes){
        char* decl = protected_to_str(votes -> data);
        taille += strlen(decl);
        nb_votes += 1;

        free(decl);

        votes = votes -> next;
    }
    
    // Taille de la preuve de travail
    char nonce[256];
    sprintf(nonce,"%d", B->nonce);
    taille += strlen(nonce);
    
    // Ajout des \0 et des espaces
    taille += (3 + nb_votes);
    
    char* bloc = (char*) (malloc(sizeof(char) * taille)); // Allocation de la mémoire
    if(bloc == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    // On remplit la chaîne de caractères

    strcpy(bloc, cle);
    strcat(bloc," ");
    strcat(bloc, previous);
    strcat(bloc," ");

    votes = B -> votes;

    while (votes){
        char* decl = protected_to_str(votes -> data);
        strcat(bloc , decl);
        free(decl);
        strcat(bloc," ");
        votes = votes -> next;
    }
    
    strcat(bloc, nonce);
    
    free(cle); free(previous);
    
    return bloc;
}

unsigned char* hash_function_SHA256(const char* s) {
    unsigned char* hash = SHA256(s,strlen(s),0);

    return hash;
}

void compute_proof_of_work(Block* B, int d){
    B -> nonce = 0;
    int verif = 0;
    char* s;

    while(verif == 0){
        B -> nonce += 1;
        char* s = block_to_str(B);
        B -> hash = hash_function_SHA256(s);

        verif = verify_zeros(B->hash,d);

        free(s);
    }
} 

int verify_block(Block* B, int d) {
    char* s = block_to_str(B);
    int res = 0;
    char* hash_actuel = hash_to_str(B->hash);
    char* hash_attendu = hash_to_str(hash_function_SHA256(s));

    if (verify_zeros(B->hash, d) && (strcmp(hash_attendu,hash_actuel) == 0)) {
        res = 1;
    }

    free(hash_attendu);
    free(hash_actuel);
    free(s);

    return res; 
}

void delete_block(Block* b){
    if(b){
       /*
        if(b->votes){
            int i = 0;
            CellProtected* tmp = NULL;
            while(b->votes){
                tmp = b->votes;
                b->votes = b->votes->next;
                free(tmp);
            }
        }*/
        free(b);
    }
}

int verify_zeros(unsigned char *hash, int d) {
    for (int i = 0; i < d/2; i++) {
        if (hash[i] != 0) {
            return 0;
        }
    }

    if ( ((d % 2) == 1) &&  ( (hash[(d/2)] & 0b11110000) != 0b00000000)) {
        return 0;
    }

    return 1;
}


char* hash_to_str(unsigned char* hash){
    int taille_chaine = 3*SHA256_DIGEST_LENGTH +1;
    char * res = malloc((taille_chaine)*sizeof(char));
    if(res == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    char buffer[4];
    int j = 0;
    for(int i = 0 ; i < SHA256_DIGEST_LENGTH ; i ++){
        sprintf(buffer,"%02x ",hash[i]);
        res[j]= buffer[0];
        res[j+1] = buffer[1];
        res[j+2] = buffer[2];

        j = j +3;
    }
    res[taille_chaine-1] = '\0';
    return res;
}

unsigned char * str_to_hash(char * st){
    unsigned char * res = (unsigned char *) malloc(SHA256_DIGEST_LENGTH*sizeof(unsigned char));
    if(res == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }
    char buffer_l[4];
    unsigned int stock;
    int j = 0;

    for(int i = 0 ; i < 3*SHA256_DIGEST_LENGTH ; i = i + 3){
        buffer_l[0] = st[i];
        buffer_l[1] = st[i+1];
        buffer_l[2] = st[i+2];
        buffer_l[3] = '\0';


        if(sscanf(buffer_l,"%02x",&stock)!=1){
            printf("Erreur de formatage du hachage hexadécimal\n");
            free(res);
            return NULL;
        }
        res[j] = stock;
        j++;
    }
    return res;
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    

CellTree* create_node(Block* b){
    CellTree* node = (CellTree*) malloc(sizeof(CellTree)); // Allocation de mémoire

    if(node == NULL){
        printf("Erreur à l'allocation de la cellule de l'arbre\n");
        return NULL;
    }

    // Initialisation des éléments

    node->block = b;
    node->height = 0;
    node->father = NULL;
    node->firstChild = NULL;
    node->nextBro = NULL;

    return node;
}
int max(int a, int b){
    if(a<b){
        return b;
    }
    return a;
}

int update_height(CellTree* father, CellTree* child){
	if (child->height >= father->height){ // On vérifie que la hauteur du fils incrémenté de 1 est inférieure à la hauteur du père
		
        father->height = max(father->height, child->height) + 1; // On modifie la hauteur du père
		
        return 1;
	} 
    
    return 0;
}

void add_child(CellTree* father, CellTree* child){
    child->father = father;
    child->nextBro = father->firstChild;
    father->firstChild = child;

    CellTree* father_cour = father;
    CellTree* child_cour = child;

    // On parcourt tous les pères et on MÀJ la hauteur de chaque noeud
    
    while( (father_cour) && (update_height(father_cour,child_cour)) ){
        child_cour = father_cour;
        father_cour = father_cour->father;
        
    }
}

void print_tree(CellTree* ab){
    if(ab) {
        char* s = hash_to_str(ab->block->hash);

        printf("%s\tHauteur = %d\n", s, ab->height);

        free(s);

        print_tree(ab->firstChild); // Appel récursif
        print_tree(ab->nextBro); // Appel récursif
    }
}

void delete_node(CellTree* node){
    if(node){
        
        if(node->block->hash != NULL) free(node->block->hash);
        
        if(node->block->previous_hash != NULL) free(node->block->previous_hash);

        if(node->block != NULL) delete_block(node->block);

        free(node);
    }

}

void delete_tree(CellTree* ab){
    if (ab) {
        if(ab->nextBro){
            delete_tree(ab->nextBro);
        }
        if(ab->firstChild){
            delete_tree(ab->firstChild);
        }
        delete_node(ab);
    }
}

CellTree* highest_child(CellTree* cell){

    CellTree* cour = cell->firstChild;
    CellTree* highest = cour;

    while(cour){ // On parcourt l'arbre
        if(highest->height < cour->height){ // Si la hauteur du noeud courant est supérieure à la hauteur de highest
            highest = cour; // MÀJ du noeud le plus haut
        }
        cour = cour->nextBro;
    }
    return highest;
}

CellTree* last_node(CellTree* tree){

    if(tree->firstChild==NULL){ // Cas d'arrêt (l'arbre est terminé)
        return tree;
    }
    else {
        return last_node(highest_child(tree)); // Appel récursif
    }
}

CellProtected* fusion_list_protected(CellProtected* l1, CellProtected* l2){
	if (l1 == NULL){
		return l2;
	}

	CellProtected* cour = l1;

	while (cour->next){ // On parcourt la liste des déclarations
		cour = cour->next;
	}
	cour->next = l2; // On modifie l1

	return l1;
}

CellProtected* fusion_votes(CellTree* tree){
    CellProtected* decl = tree->block->votes;
    CellTree* courant = highest_child(tree);

    while(courant){ // On parcourt les plus longues chaines de l'arbre
        decl = fusion_list_protected(courant->block->votes, decl); // MÀJ de tree_fusion
        courant = highest_child(courant);
    }

    return decl;
}

void submit_vote(Protected* p){
	FILE* f = fopen("Pending_votes.txt","a");
	
	char* pr = protected_to_str(p);
	fprintf(f,"%s\n",pr);
	free(pr);
	fclose(f);
}

void create_block(CellTree* tree, Key* author, int d){
    Block* b = (Block*) malloc(sizeof(Block));

    if(b==NULL){
        printf("Erreur à l'allocation du block\n");
        return;
    }

	if(tree == NULL){
		b->previous_hash = (unsigned char *) malloc(SHA256_DIGEST_LENGTH*sizeof(unsigned char));
		
        if(b->previous_hash == NULL){
            printf("Erreur à l'allocation\n");
            return;
        }

        for(int i = 0 ; i < SHA256_DIGEST_LENGTH ; i++){
			b->previous_hash[i] = '0';
		}
	}
	else{
    	CellTree* previous = last_node(tree);

		b->previous_hash = previous->block->hash;
		
	}
	
    b->author = author;
	
    b->votes = read_protected("Pending_votes.txt");

    remove("Pending_votes.txt");

    compute_proof_of_work(b,d);
    write_block("Pending_block.txt",b);

    delete_list_protected(b->votes);
	delete_block(b);
}


void add_block(int d, char* name){
	Block* new_b = read_block("Pending_block.txt");
	compute_proof_of_work(new_b,d);
	
	char buffer[256];
	if (verify_block(new_b,d)){

		sprintf(buffer,"./Blockchain/%s",name);
		write_block(buffer,new_b);
		
	} 
	remove("Pending_block.txt");


	free(new_b->author);
    //free(new_b->hash);
    //free(new_b->previous_hash);
    delete_list_protected(new_b->votes);

	delete_block(new_b);
}


int estFils(CellTree* noeud, CellTree* pere){
	char* h1 = hash_to_str(noeud->block->previous_hash);
	char* h2 = hash_to_str(pere->block->hash);

	int res = !(strcmp(h1,h2));
	free(h1);
	free(h2);
	return res;
}


CellTree* read_tree(){
	DIR* rep = opendir("./Blockchain/");
	struct dirent* dir;
	
	if(rep == NULL){
		printf("Erreur d'ouverture du dossier\n");
		return NULL;
	}
	
	CellTree** T;
	int size_T = 0;
	if (rep != NULL){
		while ((dir = readdir(rep))){
			if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
				size_T++;
			}
		}
	} 
	

	T = (CellTree**)(malloc(sizeof(CellTree*)*size_T));
	if (T == NULL){
		printf("Erreur d'allocation de la mémoire !\n");
		return NULL;
	}

    for(int i = 0; i < size_T ; i++){
          T[i] = NULL;
    }

	rewinddir(rep);

	CellTree* noeud;
	int n = 0;
	Block* block;
	char* nom_f_block;
	if (rep != NULL){
		
		while ((dir = readdir(rep))){
			if (strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0){
				
				char nom_f_block[271];

				sprintf(nom_f_block,"./Blockchain/%s",dir->d_name);

			
				block = read_block(nom_f_block);
				
				noeud = create_node(block);
				T[n] = noeud;

	
				n++;
			}

		}
	}

	rewinddir(rep);

	CellTree* n_cour; 
	CellTree* fils_potentiel;

	int a_un_pere;
	int racine_trouvee = 0;
	CellTree* frere_orphelin;
	CellTree * racine;

	for (int i = 0; i < size_T; i++){
		n_cour = T[i];
		a_un_pere = 0;
		for (int j = 0; j < size_T; j++){
			fils_potentiel = T[j];
			if ( estFils(fils_potentiel,n_cour)){
				add_child(n_cour,fils_potentiel);
				a_un_pere = 1;
			}
		}
		if (a_un_pere==0){
			if(!racine_trouvee){
				frere_orphelin = T[i];
				racine = T[i];
				racine_trouvee = 1; 
				
			}
			else{
				frere_orphelin->nextBro = T[i];
			}
		}

		
	}

  CellTree *racine2 = NULL;
  for (int i = 0; i < size_T; i++)
  {
    if (T[i]->father == NULL)
    {
      racine2 = T[i];
    }
  }


	free(T);

    closedir(rep);

	return racine2;
}

Key* compute_winner_BT(CellTree* tree, CellKey* candidates, CellKey* voters, int sizeC, int sizeV){

    CellProtected* decl = fusion_votes(tree);

    //anti_fraude(&decl); -> déjà fait dans compute winner


    Key* gagnant = compute_winner(decl, candidates, voters, sizeC, sizeV);

    return gagnant;
}