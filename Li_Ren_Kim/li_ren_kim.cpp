#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <bits/stdc++.h>

using namespace std;

pairing_t pairing;

//通配符取-1
vector<vector<int>> S = {
        {1,2},{3,4,5},{6,7,8,9},{10,11,12,13,14}
};

struct Ui{
    element_t U;
};

struct PK{
    element_t G,G1,G2,G3,U0;
    vector<Ui> U;
    PK():U(S.size()){}
};

struct SK_ID_L{
    element_t D0,D1,D2;
    vector<int> D3;
    SK_ID_L():D3(S.size()){}
};

struct Ti{
    element_t T;
    bool isvaild;
};

struct CT{
    element_t C0,C1,C2,E;
    vector<Ti> T;
    CT():T(S.size()){}
};

void int_to_hash(int number,element_t &t) {
    char* charArray =(char*)malloc(sizeof(char) * 10);
    sprintf(charArray, "%d", number);
    size_t len = strlen(charArray);
    element_from_hash(t,(void*)charArray,len);
    free(charArray);
}

class AA{
private:
    element_t alpha,msk,M;
    SK_ID_L skl;
    //系统建立
    void setup(){
        //初始化
        element_init_Zr(alpha,pairing);
        element_init_G1(msk,pairing);
        element_init_G1(pk.G,pairing);
        element_init_G1(pk.G1,pairing);
        element_init_G1(pk.G2,pairing);
        element_init_G1(pk.G3,pairing);
        element_init_G1(pk.U0,pairing);
        for(int i = 0;i < S.size();i++){
            element_init_G1(pk.U[i].U,pairing);

            element_random(pk.U[i].U);
        }
        //选取pk
        element_random(pk.G);
        element_random(pk.G2);
        element_random(pk.G3);
        element_random(pk.U0);
        //选取alpha
        element_random(alpha);
        //计算G1 msk;
        element_mul_zn(pk.G1,pk.G,alpha);
        element_mul_zn(msk,pk.G,alpha);
    }

public:
    PK pk;
    CT ct;
    AA(){
        setup();
    }
    //生成密钥
    void keygen(vector<int> &L,string ID){
        element_t r,tempG1,ID_hash;
        //初始化
        element_init_Zr(r,pairing);
        element_init_Zr(ID_hash,pairing);
        element_init_G1(tempG1,pairing);
        element_init_G1(skl.D0,pairing);
        element_init_G1(skl.D1,pairing);
        element_init_Zr(skl.D2,pairing);
        //选取r
        element_random(r);
        //计算D0
        element_mul_zn(skl.D0,pk.G2,alpha);
        char charID[ID.size()+1];
        strcpy(charID,ID.c_str());
        element_from_hash(ID_hash,(void*)charID,sizeof(charID));
        element_mul_zn(tempG1,pk.U0,ID_hash);
        for(int i = 0;i < S.size();i++){
            element_t tempZr,tempG1mul;
            element_init_G1(tempG1mul,pairing);
            element_init_Zr(tempZr,pairing);
            int_to_hash(L[i],tempZr);
            element_mul_zn(tempG1mul,pk.U[i].U,tempZr);
            element_add(tempG1,tempG1,tempG1mul);
            //清除临时变量
            element_clear(tempZr);
            element_clear(tempG1mul);
        }
        element_add(tempG1,tempG1,pk.G3);
        element_mul_zn(tempG1,tempG1,r);
        element_add(skl.D0,skl.D0,tempG1);
        //计算D1
        element_mul_zn(skl.D1,pk.G,r);
        //计算D2
        element_set(skl.D2,ID_hash);
        //D3
        for(int i = 0;i < S.size();i++){
            skl.D3[i] =  L[i];
        }
        //清除临时变量
        element_clear(r);
        element_clear(tempG1);
        element_clear(ID_hash);
    }

    //验证
    void varify(){
        element_t tempGTl,tempGTr1,tempGTr2,tempG1;
        //初始化
        element_init_GT(tempGTl,pairing);
        element_init_GT(tempGTr1,pairing);
        element_init_GT(tempGTr2,pairing);
        element_init_G1(tempG1,pairing);
        //计算左等式
        pairing_apply(tempGTl,skl.D0,pk.G,pairing);
        //计算第一个右等式
        pairing_apply(tempGTr1,pk.G2,pk.G1,pairing);
        //计算G1
        element_mul_zn(tempG1,pk.U0,skl.D2);
        for(int i = 0;i < S.size();i++){
            element_t L_hash,tempG1mul;
            element_init_G1(tempG1mul,pairing);
            element_init_Zr(L_hash,pairing);
            int_to_hash(skl.D3[i],L_hash);
            element_mul_zn(tempG1mul,pk.U[i].U,L_hash);
            element_add(tempG1,tempG1,tempG1mul);
            //清除临时变量
            element_clear(tempG1mul);
            element_clear(L_hash);
        }
        element_add(tempG1,tempG1,pk.G3);
        //计算右边第二个等式
        pairing_apply(tempGTr2,tempG1,skl.D1,pairing);
        //计算右等式
        element_mul(tempGTr1,tempGTr1,tempGTr2);
        if(element_cmp(tempGTl,tempGTr1)==0){
            cout<<"验证成功！"<<endl;
        }
        else{
            cout<<"验证失败！"<<endl;
        }
        //清除临时变量
        element_clear(tempGTl);
        element_clear(tempGTr1);
        element_clear(tempGTr2);
        element_clear(tempG1);
    }

    void encrypt(vector<int> &W){
        element_t s;
        //初始化
        element_init_Zr(s,pairing);
        element_init_GT(ct.C0,pairing);
        element_init_GT(M,pairing);
        element_init_G1(ct.C1,pairing);
        element_init_G1(ct.C2,pairing);
        element_init_G1(ct.E,pairing);
        for(int i = 0;i < S.size();i++){
            element_init_G1(ct.T[i].T,pairing);
        }
        //选取s
        element_random(s);
        //选取M
        element_random(M);
        //计算C0
        pairing_apply(ct.C0,pk.G1,pk.G2,pairing);
        element_pow_zn(ct.C0,ct.C0,s);
        element_mul(ct.C0,ct.C0,M);
        //计算C1
        element_mul_zn(ct.C1,pk.G,s);
        //计算C2
        element_set(ct.C2,pk.G3);
        for(int i = 0;i < S.size();i++){
            if(W[i] != -1){
                element_t tempZr,tempG1;
                element_init_Zr(tempZr,pairing);
                element_init_G1(tempG1,pairing);
                int_to_hash(W[i],tempZr);
                element_mul_zn(tempG1,pk.U[i].U,tempZr);
                element_add(ct.C2,ct.C2,tempG1);
                //处理T
                element_random(ct.T[i].T);
                ct.T[i].isvaild = false;
                //清除临时变量
                element_clear(tempZr);
                element_clear(tempG1);
            }
            else{
                element_mul_zn(ct.T[i].T,pk.U[i].U,s);
                ct.T[i].isvaild = true;
            }
        }
        element_mul_zn(ct.C2,ct.C2,s);
        //计算E
        element_mul_zn(ct.E,pk.U0,s);
        //清除临时变量
        element_clear(s);
    }

    void decrypt(vector<int> &W){
        for(int i = 0;i < S.size();i++){
            if(W[i] != skl.D3[i]){
                cout<<"访问策略不匹配"<<endl;
                return;
            }
        }
        element_t C2p,tempG1,decM,tempGT1,tempGT2;
        //初始化
        element_init_G1(C2p,pairing);
        element_init_G1(tempG1,pairing);
        element_init_GT(decM,pairing);
        element_init_GT(tempGT1,pairing);
        element_init_GT(tempGT2,pairing);
        //计算C2p
        element_set(C2p,ct.C2);
        element_mul_zn(tempG1,ct.E,skl.D2);
        element_add(C2p,C2p,tempG1);
        for(int i = 0;i < S.size();i++){
            if(W[i] == -1){
                element_t tempZr,tempmul;
                element_init_Zr(tempZr,pairing);
                element_init_G1(tempmul,pairing);
                int_to_hash(W[i],tempZr);
                element_mul_zn(tempmul,ct.T[i].T,tempZr);
                element_add(C2p,C2p,tempmul);


                element_clear(tempZr);
                element_clear(tempmul);
            }
        }
        //计算GT1
        pairing_apply(tempGT1,skl.D1,C2p,pairing);
        element_mul(tempGT1,tempGT1,ct.C0);
        //计算GT2
        pairing_apply(tempGT2,skl.D0,ct.C1,pairing);
        //计算decM
        element_div(decM,tempGT1,tempGT2);
        if(element_cmp(decM,M) == 0){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败！"<<endl;
        }
        //清除临时变量
        element_clear(C2p);
        element_clear(tempG1);
        element_clear(decM);
        element_clear(tempGT1);
        element_clear(tempGT2);
    }

    void clear(){
        element_clear(alpha);
        element_clear(msk);
        element_clear(M);
        element_clear(skl.D0);
        element_clear(skl.D1);
        element_clear(skl.D2);
        element_clear(pk.G);
        element_clear(pk.G1);
        element_clear(pk.G2);
        element_clear(pk.G3);
        element_clear(pk.U0);
        element_clear(ct.C0);
        element_clear(ct.C1);
        element_clear(ct.C2);
        element_clear(ct.E);
        for(int i = 0;i < S.size();i++){
            element_clear(pk.U[i].U);
            element_clear(ct.T[i].T);
        }
    }
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);
    vector<int> L = {2,4,7,11};
    AA aa;
    aa.keygen(L,"lichaohui");
    aa.varify();
    aa.encrypt(L);
    aa.decrypt(L);
    aa.clear();
    pairing_clear(pairing);
    return 0;
}