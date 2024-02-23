#include "pbc_m.h"

#include <bits/stdc++.h>

using namespace std;

int main(int argc,char **argv){
	pbc_demo_pairing_init(pairing,argc,argv);
	Zr *zr2 = new Zr();
	Zr *zr3;

	zr2->random();
	zr3->random();

	Zr *zr1 = *zr2 + *zr3;

	pairing_clear(pairing);
	return 0;
}