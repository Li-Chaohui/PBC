#include "../pbc_my.h"
#include <bits/stdc++.h>

using namespace std;

class MSK{
public:
	G1 pk,g,m,c1,c2,m_re;
	Zr sk;
	
	void keygen(){
		g.random();
		sk.random();
		pk = sk*g;
	}

	MSK(){
		keygen();
	}
	
	void encrypt(){
		Zr k;
		G1 tempg;

		k.random();
		m.random();
		c1 = k*g;
		tempg = k*pk;
		c2 = m+tempg;
	}

	void decrypt(){
		G1 tempg;
		tempg = sk*c1;
		m_re = c2-tempg;
		if(m_re == m){
			cout<<"成功！"<<endl;
		}
	}	
};

int main(int argc,char** argv){
	pbc_demo_pairing_init(pairing,argc,argv);
	MSK msk;
	msk.encrypt();
	msk.decrypt();
	return 0;
}