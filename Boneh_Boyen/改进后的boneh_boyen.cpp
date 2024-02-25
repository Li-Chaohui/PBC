#include "../pbc_my.h"
#include <bits/stdc++.h>

using namespace std;

struct SK{
    Zr x,y;
};

struct PK{
    G1 U,V,P;
};

struct Sign{
    G1 W;
    Zr r;
};

class U{
    SK sk;
public:
    PK pk;
    Zr m;
    Sign s;
    void keygen(){
        sk.x.random();
        sk.y.random();

        pk.P.random();

        pk.U = sk.x * pk.P;
        pk.V = sk.y * pk.P;
    }

    void sign(){
        Zr temp;
        m.random();
        s.r.random();
        temp = sk.x + m + s.r * sk.y;
        s.W = temp.invert() * pk.P;
        temp.clear();
    }

    void varify(){
        GT gt1,gt2;
        G1 temp;
        temp = pk.U + m * pk.P + s.r * pk.V;
        gt1 = temp & s.W;
        gt2 = pk.P & pk.P;
        if(gt1 == gt2){
            cout<<"相同！"<<endl;
        }
        else{
            cout<<"解密失败"<<endl;
        }
    }

    void clear(){   
        pk.P.clear();
        pk.U.clear();
        pk.V.clear();

        sk.x.clear();
        sk.y.clear();

        m.clear();
        
        s.r.clear();
        s.W.clear();
    }
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    U u;
    u.keygen();
    u.sign();
    u.varify();
    u.clear();
    return 0;
}