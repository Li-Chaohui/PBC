#include "../pbc_m.h"
#include <bits/stdc++.h>

using namespace std;

typedef G1* G1s;
typedef Zr* Zrs;
typedef GT* GTs;

class MSK{
public:
    G1s pk,g,m,c1,c2,m_re;
    Zrs sk;

    void init(){
        g = new G1();
        sk = new Zr();

        m = new G1();
    }

    void keygen(){
        g->random();
        sk->random();

        pk = (*sk) * (*g);
    }

    MSK(){
        init();
        keygen();
    }

    void encrypt(){
        Zr k;
        k.random();
        m->random();
        c1 = k * (*g);
        G1s temp = (k * (*pk));
        c2 = (*m) + (*temp);

        temp->clear();
        k.clear();

        delete temp;
    }

    void decrypt(){
        G1s temp = (*sk) * (*c1);
        m_re = (*c2) - (*temp);
        if((*m_re) == (*m)){
            cout<<"成功！"<<endl;
        }
        else{
            cout<<"失败！"<<endl;
        }
        temp->clear();
        delete temp;
    }

    void clear() const{
        pk->clear();
        g->clear();
        m->clear();
        c1->clear();
        c2->clear();
        m_re->clear();
        sk->clear();

        delete pk;
        delete g;
        delete m;
        delete c1;
        delete c2;
        delete m_re;
        delete sk;
    }
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    MSK msk;
    msk.encrypt();
    msk.decrypt();
    msk.clear();
    return 0;
}