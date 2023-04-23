#include "dev_out_crypto.h"

int is_prime_naive(long p){

    for (int i = 3; i < p; i++) { // On parcourt tous les entiers compris entre 3 et p
        if (p % i == 0) { // Si p est divisible par i alors p n'est pas premier
            return 0;
        }
    }

    return 1;
}

long modpow_naive(long a, long m, long n) { 
    long res = a;

    for (int i = 1; i < m; i++) { // On multiplie n-1 fois res par a
        res *= a;
    }
    res %= n; // On calcule le modulo de res par n

    return res;
}

long modpow(long a, long m, long n){
    a = a % n;

    if (m == 0) { // Un nombre "puissance 0" est toujours égal à 1
        return 1;
    }
    if (m == 1) { // Un nombre "puissance 1" est toujours égal à lui même
        return a;
    }
    if (m % 2 == 0) { // m est pair
        long x = modpow(a, m/2, n);
        return (x * x) % n;
    } else {
        long x = modpow(a, m/2, n);
        return (((x * x) % n) * a) % n;
    }
}

int witness (long a, long b, long d, long p) {
    long x = modpow(a,d,p);

    if (x == 1) {
        return 0;
    }
    for (long i = 0; i < b; i++) {
        if (x == p - 1) {
            return 0;
        }
    }
    return 1;
}

long rand_long(long low, long up) {
    return rand() % (up - low + 1) + low;
}

int is_prime_miller(long p, int k) {
    if (p == 2) {
        return 1;
    }

    /* On verifie que p est impair et différent de 1 */

    if (!(p & 1) || p <= 1) {
        return 0;
    }

    /* On détermine b et d */

    long b = 0;
    long d = p - 1;

    while(!(d & 1)) {
        d = d/2;
        b = b + 1;
    }

    /* On genere k valeurs pour a, et on teste si c'est un témoin */

    long a;
    int i;

    for (i = 0; i < k; i++) {
        a = rand_long(2, p - 1);
        if (witness(a, b, d, p)) {
            return 0;
        }
    }
    return 1;
}

long random_prime_number(int low_size, int up_size, int k) {
    long low = 2, up = 2;

    for (int i = 1; i < low_size - 1 ; i++) { // On détermine le plus petit long possible de low_size bits
        low *= 2;
    }
    for (int i = 1; i < up_size ; i++) { // On détermine le plus grand lon g possible de up_size bits
        up *= 2;
    }
    up -= 1;

    long p;
    int i = 0;

    while (i != 1) { // On détermine un p premier
        p = rand_long(low, up);
        i = is_prime_miller(p, k);
    }

    return p;
}

long extended_gcd(long s, long t, long *u, long *v) {
    if (s == 0) { 
        *u = 0;
        *v = 1;
        return t;
    }
    long uPrim, vPrim;
    long gcd = extended_gcd(t%s, s, &uPrim, &vPrim);
    *u = vPrim - (t/s) * uPrim;
    *v = uPrim;

    return gcd;
}

void generate_key_values(long p, long q, long* n, long* s, long* u) {
    *n = p * q;
    int t = (p-1) * (q-1);
    long v;

    while ((extended_gcd(*s, t, u, &v)!=1) && (*s != t)) {
        *s = rand_long(1, t);
    }
}

long* encrypt(char* chaine, long s, long n) {
    int size = (strlen(chaine));
    long* encrypted = (long*) malloc(sizeof(long) * size);
    if(encrypted == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }

    for (int i = 0; i < size; i++) { // On crypte chaque caractère de la chaine avec modpow
        encrypted[i] = modpow(chaine[i], s, n);
    }

    return encrypted;
}

char* decrypt(long* crypted, int size, long u, long n) {
    char* decrypted = (char*) malloc(sizeof(char)*(size+1));
    if(decrypted == NULL){
        printf("Erreur à l'allocation\n");
        return NULL;
    }

    for (int i = 0; i < size; i++) { // On décrypte chaque nombre de crypted avec modpow
        decrypted[i] = modpow(crypted[i], u, n);
    }
    decrypted[size] = '\0'; // On ajoute le dernier caractère '\0' systématiquement

    return decrypted;
}

void print_long_vector(long *result, int size) {
    printf("Vector: [");
    for (int i = 0; i < size; i++) { // On parcourt chaque élément de résult et on l'affiche sous forme de vecteur
        if (i == size - 1) {
            printf("%lx]\n", result[i]);
        } else {
            printf("%lx \t", result[i]);
        }
    }
}