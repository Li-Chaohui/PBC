#include "pbc_my.h"
#include <bits/stdc++.h>

using namespace std;

vector<vector<int>> S = {
    {1,2},{3,4,5},{6,7,8,9},{10,11,12,13,14}
};

struct PK{
    G1 G,G_1,G2,G3,U0,Un1;
    vector<G1> U;
    PK():U(S.size()){}
};

struct SK1{
    G1 D10,D11;
    Zr D3;
    vector<int> D4;
    SK1():D4(S.size()+1){}
};

struct SK2{
    G1 D20,D21;
};

struct SK{
    SK1 sk1;
    SK2 sk2;
};

struct CT{
    GT C0;
    G1 C1,C2,C3,E;
};

void int_to_hash(int number,Zr &t) {
    char* charArray =(char*)malloc(sizeof(char) * 10);
    sprintf(charArray, "%d", number);
    size_t len = strlen(charArray);
    element_from_hash(t.e,(void*)charArray,len);
    free(charArray);
}

void toIDhash(string ID,Zr &ID_hash){
    char charID[ID.size()+1];
    strcpy(charID,ID.c_str());
    element_from_hash(ID_hash.e,(void*)charID,sizeof(charID));
}

class AA{
private:
    void setup(){
        Zr alpha,alpha1,alpha2;
        //生成G G2 G3 U0 Un1
        pk.G.random();
        pk.G2.random();
        pk.G3.random();
        pk.U0.random();
        pk.Un1.random();
        //生成U
        for(int i = 0;i < S.size();i++){
            pk.U[i].random();
        }
        //选取alpha,alpha1
        alpha.random();
        alpha1.random();
        //计算alpha2
        alpha2 = alpha - alpha1;
        //计算G1,OK，AK
        pk.G_1 = alpha * pk.G;
        OK = alpha1 * pk.G2;
        AK = alpha2 * pk.G2;
        //清除临时变量
        alpha.clear();
        alpha1.clear();
        alpha2.clear();
    }

public:
    PK pk;
    G1 OK,AK;
    Zr ID_hash;
    GT M;
    
    AA(string ID){
        setup();
        toIDhash(ID,ID_hash);
    }
    void kengen(SK2 &sk2,vector<int> &L){
        Zr r2,tempL;
        r2.random();
        int_to_hash(L[S.size()],tempL);
        sk2.D20 = AK + r2 * (tempL * pk.Un1);
        sk2.D21 = r2 * pk.G;
    }
    void encrypt(vector<int> &W,CT &ct){
        Zr s,tempZr;
        G1 tempG1;
        s.random();
        M.random();
        ct.C0 = M * ((pk.G_1 & pk.G2)^s);
        ct.C1 = s * pk.G;
        for(int i = 0;i < S.size();i++){
            Zr Lhash;
            G1 tempmul;
            int_to_hash(W[i],Lhash);
            tempmul = Lhash * pk.U[i];

            tempG1 = tempG1 + tempmul;
        }
        tempG1 = tempG1 + pk.G3;
        ct.C2 = s * tempG1;
        int_to_hash(W[S.size()],tempZr);
        ct.C3 = s * (tempZr * pk.Un1);
        ct.E = s * pk.U0;
    }
};

class KG_CSP{
public:
    void keygen(SK1 &sk1,G1 &OK,Zr &ID_hash,PK &pk,vector<int> &L){
        Zr r1;
        G1 tempG1;
        r1.random();
        for(int i = 0;i < S.size();i++){
            G1 temp_mul;
            Zr tempL;
            int_to_hash(L[i],tempL);
            temp_mul = tempL * pk.U[i];
            tempG1 = tempG1 + temp_mul;

            temp_mul.clear();
            tempL.clear();
        }
        ID_hash.put();
        tempG1 = tempG1 + pk.G3 + (ID_hash * pk.U0);
        tempG1 = r1 * tempG1;
        sk1.D10 = OK + tempG1;
        sk1.D11 = r1 * pk.G;
        sk1.D3 = ID_hash;
        for(int i = 0;i < S.size() + 1;i++){
            sk1.D4[i] = L[i];
        }

        r1.clear();
        tempG1.clear();
    }
};

class User{
public:
    SK sk;
    void varify(PK &pk){
        GT l,r1,r2,r3;
        G1 tempG1;
        Zr Lhash;
        l = (sk.sk1.D10 + sk.sk2.D20) & pk.G;
        r1 = pk.G2 & pk.G_1;
        tempG1 = sk.sk1.D3 * pk.U0;
        for(int i = 0;i < S.size();i++){
            Zr hashL;
            G1 tempmul;
            int_to_hash(sk.sk1.D4[i],hashL);
            tempmul = hashL * pk.U[i];

            tempG1 = tempG1 + tempmul;
        }
        tempG1 = tempG1 + pk.G3;
        r2 = tempG1 & sk.sk1.D11;
        int_to_hash(sk.sk1.D4[S.size()],Lhash);
        tempG1 = Lhash * pk.Un1;
        r3 = tempG1 & sk.sk2.D21;
        r1 = r1 * r2 *r3;
        if(r1 == l){
            cout<<"验证成功！"<<endl;
        }
        else{
            cout<<"验证失败！"<<endl;
        }
    }
    void decrypt(CT &ct,GT &M){
        GT decM,fz,fm;
        G1 C2p;
        C2p = ct.C2 + (sk.sk1.D3 * ct.E);
        fz = ct.C0 * (sk.sk1.D11 & C2p) * (sk.sk2.D21 & ct.C3);
        fm = (sk.sk1.D10 & ct.C1) * (sk.sk2.D20 & ct.C1);
        decM = fz / fm;
        if(decM == M){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败！"<<endl;
        }
    }
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);

    vector<int> L = {1,1,1,1,1};
    AA aa("lichaohui");
    KG_CSP kg;
    User u;
    CT ct;
    kg.keygen(u.sk.sk1,aa.OK,aa.ID_hash,aa.pk,L);
    aa.kengen(u.sk.sk2,L);
    u.varify(aa.pk);
    aa.encrypt(L,ct);
    u.decrypt(ct,aa.M);
    pairing_clear(pairing);
    return 0;
}
