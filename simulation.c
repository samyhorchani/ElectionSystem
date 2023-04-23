#include "bpd.h"

#define D 2 //nombre de 00 pour sécuriser le hash
#define VOTANTS 1000
#define CANDIDATS 5
#define NB_VOTE_PAR_BLOCK 10

/* IMPORTANT : FAIRE UN MAKE CLEAN AVANT DE RELANCER L'EXÉCUTION DU PROGRAMME */

int main(){
    srand(time(NULL));
    printf("\nVOUS ENTREZ DANS LA SIMULATION °°\n\n");
    

    printf("Il y a %d citoyens inscrits sur la liste électorale.\n", VOTANTS);
    printf("Ils pourront voter pour un des candidats suivants :\n");
    generate_random_data(VOTANTS, CANDIDATS);

    CellKey* votants = read_public_keys("./RandomDatas/keys.txt");
    CellKey* candidats = read_public_keys("./RandomDatas/candidates.txt");
    CellProtected* decl = read_protected("./RandomDatas/declarations.txt");
    print_list_keys(candidats);


    printf("\nNous attendons que tous les votants aient soumis leur vote.\n");

    CellProtected* tmp = decl;
    CellTree* tree = NULL;
  
    int i = 1;
    int nb_votes = 0;

    CellTree* tree_tmp = NULL;
    while (tmp) {

        if (tmp -> next) {
            if (nb_votes < NB_VOTE_PAR_BLOCK) {
 
                submit_vote(tmp -> data);

            } else {
                nb_votes = 0;

                if(tree_tmp != NULL){
                    delete_tree(tree);
                }
                tree = read_tree();
                tree_tmp = tree;


                create_block(tree, tmp -> data -> pKey, D);
   
                char name[256];
                sprintf(name, "B%d", i);
                printf("Création du fichier %s.txt\n", name);

                add_block(D, name);

                submit_vote(tmp -> data);

                i++;
            }

            nb_votes++;
            
            tmp = tmp -> next;
        } else {
            submit_vote(tmp -> data);
            
            if(tree_tmp != NULL){
                    delete_tree(tree);
            }
            tree = read_tree();

            tree_tmp = tree;
            create_block(tree, tmp -> data -> pKey, D);
            
            char name[256];
            sprintf(name, "B%d", i);
            printf("Création du fichier %s.txt\n", name);

            add_block(D, name);

            tmp = tmp -> next;
            nb_votes = 0;
        }
    }

    printf("Nous avons récupéré tous les votes et vérifié leur validité.\n\n");
    
    tree = read_tree();
    print_tree(tree); // Mettre un affichage car je ne sais pas à quoi ça sert

    printf("\n\nRésultat des élections :\n");

    compute_winner_BT(tree, candidats, votants, CANDIDATS, VOTANTS);

    printf("\nFIN DE LA SIMULATION ^^\n\n");

    delete_list_keys(votants);
    delete_list_keys(candidats);
    delete_list_protected(decl);
    delete_tree(tree_tmp);
    delete_tree(tree);

    return 0;
}