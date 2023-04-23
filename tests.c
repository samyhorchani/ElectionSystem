#include "bpd.h"

#define D 2
#define VOTANTS 10
#define CANDIDATS 2


int main(void) {

    clock_t t1; clock_t t2;
    srand(time(NULL));


    /* On vérifie < is_prime_naive > sur des petits nombres */

    assert(is_prime_naive(1) == 1);
    assert(is_prime_naive(2) == 1);
    assert(is_prime_naive(3) == 1);
    assert(is_prime_naive(5) == 1);
    assert(is_prime_naive(10) == 0);

    /* On vérifie que < modpow_naive > et < modpow > renvoient bien le même nombre */

    assert(modpow_naive(10, 12, 14) == modpow(10, 12, 14));

    /* On détermine le plus grand entier premier analysé en moins de 2s par la fonction < is_prime_naive > */
    /* On le laisse en commentaire car son exécution prend du temps (resultats disponibles dans le compte rendu) */

    /*
    float time = 0.0;
    long res = 0;

    for (long i = 0; time < 2; i++) { // Les calculs sont longs à effectuer et ne donnent pas la même valeur d'un écosystème à l'autre
        t1 = clock();
        is_prime_naive(i);
        t2 = clock();
        time = ((float)(t2 - t1) / CLOCKS_PER_SEC);
        if (is_prime_naive(i) == 1) {
            res = i;
            printf("%ld en %f s\n", i, time);
        }
    }

    printf("Le plus grand nombre premier trouvé : %ld\n", res);
    */


    /* On compare les performances de < modpow_naive > et < modpow > */

    /*FILE* file1 = fopen("./Tests/Analyse/analyseMP.txt", "w");
    for(int i = 1; i <= 100 ; i++){
        t1  = clock();
        modpow(2,10000000*i,4);
        t2 = clock();
        printf("%d\n",i);
        fprintf(file1, "%d %f\n", 10000000*i,((float)(t2 - t1) / CLOCKS_PER_SEC));
    }
    fclose(file1);

    FILE* file2 = fopen("./Tests/Analyse/analyseMP_naive.txt", "w");
    for(int i = 1; i <= 100 ; i++){
        t1  = clock();
        modpow_naive(2,10000000*i,4);
        t2 = clock();
        printf("%d\n",i);
        fprintf(file1, "%d %f\n", 10000000*i,((float)(t2 - t1) / CLOCKS_PER_SEC));
    }
    fclose(file2);
    */

    /* On vérifie que < is_prime_naive > renvoie bien une majorité de nombre entiers premiers */

    for (int i = 0; i < 100 ; i++) {
        assert(is_prime_naive(random_prime_number(4, 5, 10)) == 1);
    }

    /* On vérifie que les fonctions < str_to_key > et < key_to_Str > créées bien la même clé et la même chaîne de caractères */

    
    Key* pKey = (Key*) malloc(sizeof(Key));
    Key* sKey = (Key*) malloc(sizeof(Key));

    init_pair_keys(pKey, sKey, 3, 7);

    char* pStr = (char*) malloc(sizeof(char) * 5);
    sprintf(pStr, "(%lx,%lx)", pKey -> val, pKey -> n);
    char* sStr = (char*) malloc(sizeof(char) * 5);
    sprintf(sStr, "(%lx,%lx)", sKey -> val, sKey -> n);
	
	char* pKey_str = key_to_str(pKey);
	char* sKey_str = key_to_str(sKey);	
	
	Key* pKey_key = str_to_key(pStr);
	Key* sKey_key = str_to_key(sStr);
	
    assert(strcmp(pKey_str, pStr) == 0);
    assert(strcmp(sKey_str, sStr) == 0);
    assert(pKey -> val == pKey_key -> val);
    assert(pKey -> n == pKey_key -> n);
    assert(sKey -> val == sKey_key -> val);
    assert(sKey -> n == sKey_key -> n);

    free(pKey); free(sKey); free(pStr); free(sStr); free(pKey_str); free(sKey_str); free(pKey_key); free(sKey_key);

    /* On vérifie que < generate_random_data > génère bien des données aléatoires */

    generate_random_data(VOTANTS, CANDIDATS);

    /* On verifie que read public fonctionne */

    CellKey* LCK = read_public_keys("./RandomDatas/candidates.txt");

    print_list_keys(LCK);

    delete_list_keys(LCK);

    /* On teste nos listes de protected */

    CellProtected* LCP = read_protected("./RandomDatas/declarations.txt");

    print_list_protected(LCP);
    anti_fraude(&LCP);
    print_list_protected(LCP);
    delete_list_protected(LCP);

    /* On teste nos tables de hachages */

    CellKey* voters = read_public_keys("./RandomDatas/keys.txt");
    CellKey* candidates = read_public_keys("./RandomDatas/candidates.txt");
    CellProtected* decl = read_protected("./RandomDatas/declarations.txt");

    printf("\n");

    Key* gagnant = compute_winner(decl, candidates, voters, 2*CANDIDATS, 2*VOTANTS);


    /* On teste nos blocs */

    /* On crée notre bloc */

    Block* B1 = (Block*)malloc(sizeof(Block));
    assert(B1);

    Key* pKey_author = (Key*) malloc(sizeof(Key));
    Key* sKey_author = (Key*) malloc(sizeof(Key));

    assert(pKey_author); assert(sKey_author);

    init_pair_keys(pKey_author, sKey_author, 3, 7);

    B1 -> author = pKey_author;

    B1 -> previous_hash = "J«»áÑyÂ«_y6{VÚÝºn³­öÏS";
    B1 -> votes = decl;
    B1 -> nonce = 0;

    /* Test compute_proof_of_work */
    /*
    FILE* file3 = fopen("./Tests/Analyse/analyseCPOW.txt", "w");
    for(int i = 1; i <= 6 ; i++){
        for(int j = 0; j< 5; j++){
            t1  = clock();
            compute_proof_of_work(B1, i);
            t2 = clock();
            printf("Tests COPW pour %d zéros \n",i);
            fprintf(file3, "%d %f\n", i,((float)(t2 - t1) / CLOCKS_PER_SEC));
        }
    }
    fclose(file3);*/

    /* On complète la preuve de travail */

    compute_proof_of_work(B1, D);
    

    /* On écrit le bloc dans un fichier et on lit le fichier créé */

    write_block("./Tests/Blockchain/B.txt", B1);
    Block* B2 = read_block("./Tests/Blockchain/B.txt");

    /* On affiche notre bloc */

    char* B2_str = block_to_str(B2);
    printf("%s\n\n", B2_str);

    if (verify_block(B2, 2) == 1) {
        printf("B2 est valide !\n\n");
    } else {
        printf("B2 n'est pas valide !\n\n");
    }

    /* On vérifie nos arbres de blocs */

    Block* tab[6];
    CellTree* nodes[6];

    int i;
    for(i = 0; i < 6; i++){
        char name[256];
        sprintf(name,"./Tests/Blockchain/B%d.txt", i);
        write_block(name, B2);
        tab[i] = read_block(name);
        nodes[i] =  create_node(tab[i]);
    }
    
    CellTree* racine = nodes[0];
    add_child(racine,nodes[1]);
    add_child(racine,nodes[2]);
    add_child(nodes[2],nodes[3]);
    add_child(nodes[2],nodes[4]);
    add_child(nodes[4],nodes[5]);
    
   
    print_tree(racine);

    CellTree* lastNode = last_node(racine);
    char* tmp1 = hash_to_str(nodes[5]->block->hash);
    char* tmp2 = hash_to_str(lastNode->block->hash);

    if ((strcmp(tmp1, tmp2) == 0) && (lastNode -> height == nodes[5] -> height)) {
        printf("\nNous avons obtenu le résulat attendu pour last_node.\n\n");
    } else {
        printf("\nNous n'avons pas obtenu le résulat attendu pour last_node.\n\n");
    }

    CellProtected* liste = fusion_votes(racine);
    printf("Liste la plus longue obtenue dans l'abre : \n");
    print_list_protected(liste);
    printf("\n");

    /* Libération de la mémoire */

    delete_list_keys(voters);
    delete_list_keys(candidates);
    delete_list_protected(decl);

    for (int i = 0; i < SHA256_DIGEST_LENGTH ; i++){
        printf ("%02x ", B1->hash[i]);        
    }
    delete_block(B1);

    free(sKey_author);
    free(pKey_author);


    free(B2->author);
    free(B2->hash);
    free(B2->previous_hash);
    delete_list_protected(B2->votes); //car B2 crée avec read_block malloc une nouvelle liste de protected
    delete_block(B2);

    free(B2_str);

    
    delete_list_protected(liste);
    for(i = 0; i < 6 ; i++){
        free(tab[i]->author);
        free(tab[i]->hash);
        free(tab[i]->previous_hash);
        //delete_cell_protected(tab[i]->votes);
        delete_block(tab[i]);

        //free(nodes[i]);
    }
    delete_tree(racine);
    

    
    free(tmp1);
    free(tmp2);


    printf("\n\nTESTS VALIDÉS !!! ^^\n\n");

    return 0;
}
