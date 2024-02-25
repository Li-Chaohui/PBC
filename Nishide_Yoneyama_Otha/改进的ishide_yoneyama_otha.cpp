#include "../pbc_my.h"
#include <bits/stdc++.h>

using namespace std;

vector<vector<int>> S = {
    {1,2},{3,4,5},{6,7,8,9}
};

struct aA_bA{
    G1 aA,bA;
};

struct PK{
    GT Y;
    G1 G;
    vector<vector<aA_bA>> AB;
    PK(){
        for(int i = 0;i < S.size();i++){
            vector<aA_bA> t(S[i].size());
            AB.emplace_back(t);
        }
    }
};

struct abi{
    Zr a,b;
};

struct MK{
    Zr w;
    vector<vector<abi>> ab;
    MK(){
        for(int i = 0;i < S.size();i++){
            vector<abi> t(S[i].size());
            ab.emplace_back(t);
        }
    }
    
};


struct Di{
    G1 D0,D1,D2;
};

struct SK{
    G1 D0;
    vector<Di> D;
    SK():D(S.size()){}
};

struct Ci{
    G1 C1,C2;
};

struct CT{
    vector<int> W;
    GT C_wave;
    G1 C0;
    vector<vector<Ci>> C;
    CT():W(S.size()){
        for(int i = 0;i < S.size();i++){
            vector<Ci> t(S[i].size());
            C.emplace_back(t);
        }
    }
};


class NYO{
private:
    MK mk;
    vector<vector<G1>> A;
    void setup(){
        pk.G.random();
        mk.w.random();
        pk.Y = (pk.G & pk.G) ^ mk.w;
        for(int i = 0;i < S.size();i++){
            for(int j = 0;j < S[i].size();j++){
                mk.ab[i][j].a.random();
                mk.ab[i][j].b.random();
                A[i][j].random();

                pk.AB[i][j].aA = mk.ab[i][j].a * A[i][j];
                pk.AB[i][j].bA = mk.ab[i][j].b * A[i][j];
            }
        }
    }

    vector<int> getIndex(vector<int> &L){
        vector<int> index(S.size());
        for(int i = 0;i < S.size();i++){
            for(int j = 0;j < S[i].size();j++){
                if(L[i] == S[i][j]){
                    index[i] = j;
                }
            }
        }
        return index;
    }
public:
    PK pk;
    NYO(){
        for(int i = 0;i < S.size();i++){
            vector<G1> t(S[i].size());
            A.emplace_back(t);
        }
        setup();
    }

    SK keygen(vector<int> &L){
        SK sk;
        vector<Zr> s(S.size());
        vector<Zr> lambda(S.size());
        vector<int> index = getIndex(L);
        Zr s_sum;
        for(int i = 0;i < S.size();i++){
            s[i].random();
            lambda[i].random();
            s_sum = s_sum + s[i];
            //计算Di0
            sk.D[i].D0 = (s[i] * pk.G) + (mk.ab[i][index[i]].a * mk.ab[i][index[i]].b * lambda[i]) * A[i][index[i]];
            //计算Di1
            sk.D[i].D1 = (mk.ab[i][index[i]].a * lambda[i]) * pk.G;
            //计算Di2
            sk.D[i].D2 = (mk.ab[i][index[i]].b * lambda[i]) * pk.G;
        }
        sk.D0 = (mk.w - s_sum) * pk.G;
        //清除临时变量
        for(int i = 0;i < S.size();i++){
            s[i].clear();
            lambda[i].clear();
        }
        s_sum.clear();
        return sk;
    }

    CT encrypt(GT &M,vector<int> &W){
        CT ct;
        Zr r;
        r.random();
        ct.C_wave = M * (pk.Y ^ r);
        ct.C0 = r * pk.G;
        vector<vector<Zr>> rij;
        for(int i = 0;i < S.size();i++){
            vector<Zr> t(S[i].size());
            rij.emplace_back(t);
            for(int j = 0;j < S[i].size();j++){
                rij[i][j].random();
                ct.W[i] = W[i];
                if(W[i] == S[i][j]){
                    ct.C[i][j].C1 = rij[i][j] * pk.AB[i][j].bA;
                    ct.C[i][j].C2 = (r - rij[i][j]) * pk.AB[i][j].aA;
                }
                else{
                    ct.C[i][j].C1.random();
                    ct.C[i][j].C2.random();
                }
            }
        }
        for(int i = 0;i < S.size();i++){
            for(int j = 0;j < S[i].size();j++){
                rij[i][j].clear();
            }
        }
        r.clear();
        return ct;
    }

    void decrypt(CT &ct,SK &sk,GT &M,vector<int> &L){
        for(int i = 0;i < S.size();i++){
            if(ct.W[i] != L[i]){
                cout<<"访问策略不匹配"<<endl;
                return;
            }
        }
        vector<int> index = getIndex(L);
        vector<pair<G1,G1>> Cp(S.size());
        GT fz,fm;
        fz = ct.C_wave;
        fm = ct.C0 & sk.D0;
        for(int i = 0;i < S.size();i++){
            Cp[i].first = ct.C[i][index[i]].C1;
            Cp[i].second = ct.C[i][index[i]].C2;

            GT gt1,gt2;
            gt1 = Cp[i].first & sk.D[i].D1;
            gt2 = Cp[i].second & sk.D[i].D2;
            fz = fz * (gt1 * gt2);

            gt1 = ct.C0 & sk.D[i].D0;
            fm = fm * gt1;

            gt1.clear();
            gt2.clear();
        }
        GT dec_M;
        dec_M = fz / fm;
        if(dec_M == M){
            cout<<"解密成功"<<endl;
        }
        else{
            cout<<"失败"<<endl;
        }
        for(int i = 0;i < S.size();i++){
            Cp[i].first.clear();
            Cp[i].second.clear();
        }
        fz.clear();
        fm.clear();
    }

    void clear(){
        for(int i = 0;i < S.size();i++){
            for(int j = 0;j < S[i].size();j++){
                mk.ab[i][j].a.clear();
                mk.ab[i][j].b.clear();

                pk.AB[i][j].aA.clear();
                pk.AB[i][j].bA.clear();

                A[i][j].clear();
            }
        }
        pk.G.clear();
        pk.Y.clear();
        mk.w.clear();
    }
};


int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    NYO nyo;
    vector<int> L = {1,5,8};
    SK sk;
    CT ct;
    GT M;
    M.random();
    sk = nyo.keygen(L);
    ct = nyo.encrypt(M,L);
    nyo.decrypt(ct,sk,M,L);
    //清除变量
    for(int i = 0;i < S.size();i++){
        sk.D[i].D0.clear();
        sk.D[i].D1.clear();
        sk.D[i].D2.clear();
        for(int j = 0;j < S[i].size();j++){
            ct.C[i][j].C1.clear();
            ct.C[i][j].C2.clear();
        }
    }
    ct.C0.clear();
    ct.C_wave.clear();
    sk.D0.clear();
    nyo.clear();
    pairing_clear(pairing);
    return 0;
}