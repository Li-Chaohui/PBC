#include "../pbc_my.h"
#include <bits/stdc++.h>

using namespace std;


#define N 5

struct Ai{
    G1 A,A_hat,A_star;
};

struct PK{
    GT Y;
    G1 G;
    vector<Ai> A;
    PK():A(N){}
};

struct ai{
    Zr a,a_hat,a_star;
};

struct MK{
    Zr w;
    vector<ai> a;
    MK():a(N){}
};

struct Di{
    G1 D,D_star;
};

struct SK{
    G1 D0;
    vector<Di> D;
    SK():D(N){}
};

struct CT{
    vector<int> W;
    GT c_wave;
    G1 C0;
    vector<G1> C;
    CT():W(N),C(N){}
};

class CN{
private:
    MK mk;
    void setup(){
        pk.G.random();
        mk.w.random();

        pk.Y = pk.G & pk.G;
        pk.Y = pk.Y ^ mk.w;

        for(int i = 0;i < N;i++){
            mk.a[i].a.random();
            mk.a[i].a_hat.random();
            mk.a[i].a_star.random();

            pk.A[i].A = mk.a[i].a * pk.G;
            pk.A[i].A_hat = mk.a[i].a_hat * pk.G;
            pk.A[i].A_star = mk.a[i].a_star * pk.G;
        }
    }

    
public:
    PK pk;

    SK kengen(const vector<int> &L){
        SK sk;
        vector<Zr> s(N);
        Zr s_sum;
        for(int i = 0;i < N;i++){
            s[i].random();
            s_sum = s_sum + s[i];
            sk.D[i].D_star = (s[i] / mk.a[i].a_star) * pk.G;
            if(L[i] == 1){
                sk.D[i].D = (s[i] / mk.a[i].a) * pk.G; 
            }
            else if(L[i] == 0){
                sk.D[i].D = (s[i] / mk.a[i].a_hat) * pk.G;
            }
        }
        sk.D0 = (mk.w - s_sum) * pk.G;
        s_sum.clear();
        for(auto &t:s){
            t.clear();
        }
        return sk;
    }   


    CT encrypt(GT &M,vector<int> &W){
        CT ct;
        Zr r;
        r.random();
        ct.c_wave = M * (pk.Y ^ r);
        ct.C0 = r * pk.G;
        for(int i = 0;i < N;i++){
            if(W[i] == 1){
                ct.C[i] = r * pk.A[i].A;
            }
            else if(W[i] == 0){
                ct.C[i] = r * pk.A[i].A_hat;
            }
            else{
                ct.C[i] = r * pk.A[i].A_star;
            }
        }
        r.clear();
        for(int i = 0;i < N;i++){
            ct.W[i] = W[i];
        }
        return ct;
    }

    void decrypt(CT &ct,SK &sk,vector<int> &L,GT &M){
        for(int i = 0;i < N;i++){
            if(ct.W[i] != L[i]){
                cout<<"访问策略不匹配"<<endl;
                return;
            }
        }
        vector<G1> Dp(N);
        for(int i = 0;i < N;i++){
            if(ct.W[i] != -1){
                Dp[i] = sk.D[i].D;
            }
            else{
                Dp[i] = sk.D[i].D_star;
            }
        }
        GT gt1,gt2;
        gt1 = ct.C0 & sk.D0;
        gt2 = ct.C[0] & Dp[0];
        for(int i = 1;i < N;i++){
            gt2 = gt2 * (ct.C[i] & Dp[i]);
        }
        GT decM;
        decM = ct.c_wave / (gt1 * gt2);
        if(decM == M){
            decM.put();
            cout<<endl;
            M.put();
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败！"<<endl;
        }
        gt1.clear();
        gt2.clear();
        decM.clear();
        for(int i = 0;i < N;i++){
            Dp[i].clear();
        }
    }

    void clear(){
        for(int i = 0;i < N;i++){
            mk.a[i].a.clear();
            mk.a[i].a_hat.clear();
            mk.a[i].a_star.clear();

            pk.A[i].A.clear();
            pk.A[i].A_hat.clear();
            pk.A[i].A_star.clear();
        }
        pk.G.clear();
        pk.Y.clear();
        mk.w.clear();
    }

};

int main(int argc,char **argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    CN cn;
    vector<int> L = {1,0,0,1,1};
    SK sk;
    sk = cn.kengen(L);
    GT M;
    M.random();
    vector<int> W = {1,0,0,1,1};
    CT ct;
    ct = cn.encrypt(M,W);
    cn.decrypt(ct,sk,L,M);
    cn.clear();
    pairing_clear(pairing);
    return 0;
}