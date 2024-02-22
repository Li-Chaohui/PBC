#include "../pbc_my.h"
#include <bits/stdc++.h>

using namespace std;

#define N 10

vector<int> isvaild = {-1,1,0,1,0,1,0,1,0,1,0};

struct PK{
    G1 G,V;
    vector<G1> Gn;
    PK():Gn(2*N+1){}
};

struct CT{
    G1 C0,C1;
    GT C2;
    void operator=(CT ct){
        C0 = ct.C0;
        C1 = ct.C1;
        C2 = ct.C2;
    }
};


class MSK{
    G1 Gn1;
    void setup(){
        //生成基点G
        pk.G.random();
        //随即生成alpha
        Zr alpha;
        alpha.random();
        for(int i = 1;i <= 2*N;i++){
            Zr pow;
            pow = i;
            if(i!=N+1){
                pk.Gn[i] = (alpha^pow)*pk.G;
            }
            else{
                Gn1 = (alpha^pow)*pk.G;
            }
        }
        Zr gamma;
        gamma.random();
        msk = gamma;
        //生成用户密钥
        for(int i = 0;i <= N;i++){
            D[i] = gamma*pk.Gn[i];
        }
        pk.V = gamma*pk.G;
    }
public:
    PK pk;
    Zr msk;
    vector<G1> D;
    MSK():D(N+1){
        setup();
    }
    CT encrypt(){
        CT ct;
        Zr t;
        t.random();
        ct.C2 = (pk.G&Gn1)^t;
        ct.C0 = t*pk.G;
        G1 tempsum;
        tempsum = pk.V;
        for(int j = 1;j <= N;j++){
            if(isvaild[j]==1){
                tempsum = tempsum + pk.Gn[N+1-j];
            }
        }
        ct.C1 = t*tempsum;
        return ct;
    }
    void decrypt(int i,CT &ct){
        if(isvaild[i] == 0){
            cout<<"用户不合法"<<endl;
            return;
        }
        GT fz,fm;
        fz = pk.Gn[i]&ct.C1;
        G1 tempsum;
        tempsum = D[i];
        for(int j = 1;j <= N;j++){
            if(i!=j && isvaild[j] == 1){
                tempsum = tempsum + pk.Gn[N+1-j+i];
            }
        }
        fm = tempsum&ct.C0;
        GT dec_K;
        dec_K = fz/fm;
        if(dec_K == ct.C2){
            cout<<"成功！"<<endl;
        }
        else{
            cout<<"失败！"<<endl;
        }
    }
    void clear(){
        
        msk.clear();
        pk.G.clear();
        pk.V.clear();
        Gn1.clear();

        for(int i = 0;i < pk.Gn.size();i++){
            pk.Gn[i].clear();
        }

        for(int i = 0;i <D.size();i++){
            D[i].clear();
        }
    }
};

int main(int argc,char **argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    MSK msk;
    CT ct;
    ct = msk.encrypt();
    msk.decrypt(1,ct);

    //清除变量
    msk.clear();
    ct.C0.clear();
    ct.C1.clear();
    ct.C2.clear();
    return 0;
}