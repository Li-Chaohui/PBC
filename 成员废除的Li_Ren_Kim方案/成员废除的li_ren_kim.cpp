#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <bits/stdc++.h>

pairing_t pairing;

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);

    pairing_clear(pairing);
    return 0;
}