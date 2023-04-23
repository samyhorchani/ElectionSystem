#ifndef DEV_OUT_CRYPTO_H
#define DEV_OUT_CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <assert.h>

/* Prototypes */

int is_prime_naive(long p); // retourne 1 si p est premier et 0 sinon (on suppose que p est impair)

long modpow_naive(long a, long m, long n); // retourne la valeur (a^m) mod n
long modpow(long a, long m, long n); // retourne la valeur (a^m) mod n (récursive)

int witness(long a, long b, long d, long p); // retourne 1 si a est un témoin de Miller pour p et 0 sinon
long rand_long(long low, long up); // retourne un entier compris entre ces deux entiers
int is_prime_miller(long p, int k); // retourne 0 dès qu'un témoin de Miller a été trouvé et 0 sinon

long random_prime_number(int low_size, int up_size, int k); // retourne un nombre premier de taille comprise entre low_size et up_size

long extended_gcd(long s, long t, long *u, long *v); // retourne PGCD(s, t), l'entier u et l'entier v
void generate_key_values(long p, long q, long* n, long* s, long* u); // retourne la clé publique (s, n) et la clé secrète (u, n)

long* encrypt(char* chaine, long s, long n); // retourne le message chiffré
char* decrypt(long* crypted, int size, long u, long n); // retourne le message déchiffrer

void print_long_vector(long *result, int size); // affiche un vecteur d'entiers

#endif