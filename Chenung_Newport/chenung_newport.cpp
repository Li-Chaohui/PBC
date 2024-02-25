#include "../my.h"


using namespace std;

#define SIZE 5

pairing_t pairing;

struct a{
    element_t a;
    element_t a_hat;
    element_t a_star;
};

struct A{
    element_t A;
    element_t A_hat;
    element_t A_star;
};

struct D{
    element_t D;
    element_t D_star;
};

struct MSK{
    element_t w;
    vector<a> a_set;
    MSK():a_set(SIZE){}
};

struct PK{
    element_t Y,G;
    vector<A> A_set;
    PK():A_set(SIZE){}
};

struct SK_l{
    element_t D0;
    vector<D> D_set;
    SK_l():D_set(SIZE){}
};

struct CT{
    vector<int> W;
    element_t C_,C0;
    vector<element_t> Ci;
    CT():W(SIZE),Ci(SIZE){}
};

class SP{
private:
    MSK msk;//w,a_set
    CT ct;
    element_t M;

    void Setup(){
        element_init_Zr(msk.w,pairing);
        element_init_GT(pk.Y,pairing);
        element_init_G1(pk.G,pairing);

        element_random(msk.w);
        element_random(pk.G);//选取基点
        pairing_apply(pk.Y,pk.G,pk.G,pairing);
        element_pow_zn(pk.Y,pk.Y,msk.w);
        for(int i = 0;i < SIZE;i++){
            element_init_Zr(msk.a_set[i].a,pairing);
            element_init_Zr(msk.a_set[i].a_hat,pairing);
            element_init_Zr(msk.a_set[i].a_star,pairing);

            element_random(msk.a_set[i].a);
            element_random(msk.a_set[i].a_hat);
            element_random(msk.a_set[i].a_star);

            element_init_G1(pk.A_set[i].A,pairing);
            element_init_G1(pk.A_set[i].A_hat,pairing);
            element_init_G1(pk.A_set[i].A_star,pairing);

            element_mul_zn(pk.A_set[i].A,pk.G,msk.a_set[i].a);
            element_mul_zn(pk.A_set[i].A_hat,pk.G,msk.a_set[i].a_hat);
            element_mul_zn(pk.A_set[i].A_star,pk.G,msk.a_set[i].a_star);
        }
    }

    void init(){
        Setup();
        //1 0 0 1 -1
        ct.W[0] = 1;
        ct.W[1] = 0;
        ct.W[2] = 0;
        ct.W[3] = 1;
        ct.W[4] = -1;

    }


public:
    PK pk;//Y,G,A_set

    SP(){
        init();
    }

    SK_l* KeyGen(vector<int> L){
        SK_l *sk = new SK_l();
        vector<element_t> Si(SIZE);
        element_t S,temp_Zr;
        element_init_Zr(temp_Zr,pairing);
        element_init_Zr(S,pairing);
        for(auto &t:Si){
            element_init_Zr(t,pairing);
            element_random(t);
            element_add(S,S,t);
        }
        element_init_G1(sk->D0,pairing);
        element_sub(temp_Zr,msk.w,S);
        element_mul_zn(sk->D0,pk.G,temp_Zr);
        for(int i = 0;i<L.size();i++){
            element_t temp_si_ai;
            element_init_Zr(temp_si_ai,pairing);
            element_init_G1(sk->D_set[i].D,pairing);
            element_init_G1(sk->D_set[i].D_star,pairing);
            if(L[i]){//L[i]==1
                element_div(temp_si_ai,Si[i],msk.a_set[i].a);
                element_mul_zn(sk->D_set[i].D,pk.G,temp_si_ai);
            }
            else{
                element_div(temp_si_ai,Si[i],msk.a_set[i].a_hat);
                element_mul_zn(sk->D_set[i].D,pk.G,temp_si_ai);
            }
            element_div(temp_si_ai,Si[i],msk.a_set[i].a_star);
            element_mul_zn(sk->D_set[i].D_star,pk.G,temp_si_ai);
            
            
            element_clear(temp_si_ai);
        }

        for(int i = 0;i<SIZE;i++){
            element_clear(Si[i]);
        }
        element_clear(S);
        element_clear(temp_Zr);
        return sk;
    }

    void Encrypt(){
        element_t r,temp_GT;
        element_init_Zr(r,pairing);
        element_random(r);
        
        element_init_GT(ct.C_,pairing);
        element_init_GT(temp_GT,pairing);
        element_init_GT(M,pairing);
        element_init_G1(ct.C0,pairing);
        element_pow_zn(temp_GT,pk.Y,r);
        
        element_random(M);
        element_mul(ct.C_,M,temp_GT);
        element_mul_zn(ct.C0,pk.G,r);

        for(int i = 0;i < ct.W.size();i++){
            element_init_G1(ct.Ci[i],pairing);
            if(ct.W[i] == 1){
                element_mul_zn(ct.Ci[i],pk.A_set[i].A,r);
            }
            else if(ct.W[i] == 0){
                element_mul_zn(ct.Ci[i],pk.A_set[i].A_hat,r);
            }
            else{
                element_mul_zn(ct.Ci[i],pk.A_set[i].A_star,r);
            }
        }

        element_clear(r);
        element_clear(temp_GT);
    }

    void Decrypt(vector<int> L,SK_l *skl){
        for(int i = 0;i < SIZE;i++){
            if(L[i] != ct.W[i]){
                cout<<" 解密失败 L与访问策略不匹配 "<<endl;
                return;
            }
        }
        element_t dc_M,temp_GT1,temp_GT2;
        element_init_GT(dc_M,pairing);
        element_init_GT(temp_GT1,pairing);
        element_init_GT(temp_GT2,pairing);
        vector<element_t> D_p(SIZE);
        for(auto &t:D_p){
            element_init_G1(t,pairing);
        }
        for(int i = 0;i < SIZE;i++){
            if(ct.W[i]!=-1){
                element_set(D_p[i],skl->D_set[i].D);
            }
            else{
                element_set(D_p[i],skl->D_set[i].D_star);
            }
        }
        pairing_apply(temp_GT1,ct.C0,skl->D0,pairing);
        element_set(temp_GT2,temp_GT1);
        for(int i = 0;i < SIZE;i++){
            pairing_apply(temp_GT1,ct.Ci[i],D_p[i],pairing);
            element_mul(temp_GT2,temp_GT2,temp_GT1);
        }
        element_div(dc_M,ct.C_,temp_GT2);
        if(element_cmp(dc_M,M)==0){
            element_printf("M = %B\n",M);
            element_printf("dc_M = %B\n",dc_M);
            cout<<" 解密成功！"<<endl;
        }
        else{
            cout<<" 解密失败 "<<endl;
        }
        for(int i = 0;i < SIZE;i++){
            element_clear(D_p[i]);
        }
        element_clear(dc_M);
        element_clear(temp_GT1);
        element_clear(temp_GT2);
    }
    void clear(){
        for(int i = 0;i < SIZE;i++){
            element_clear(msk.a_set[i].a);
            element_clear(msk.a_set[i].a_hat);
            element_clear(msk.a_set[i].a_star);

            element_clear(ct.Ci[i]);

            element_clear(pk.A_set[i].A);
            element_clear(pk.A_set[i].A_hat);
            element_clear(pk.A_set[i].A_star);

        }
        
        element_clear(msk.w);
        element_clear(ct.C_);
        element_clear(ct.C0);
        element_clear(M);
        element_clear(pk.Y);
        element_clear(pk.G);
    }
};

void clear_SKl(SK_l *sk){
    for(int i = 0;i<SIZE;i++){
        element_clear(sk->D_set[i].D);
        element_clear(sk->D_set[i].D_star);
    }
    element_clear(sk->D0);
}

int main(int argc,char **argv){
    pbc_demo_pairing_init(pairing,argc,argv);

    SP nist;
    vector<int> u1_l = {1,1,0,0,-1};
    SK_l *u1 = nist.KeyGen(u1_l);
    vector<int> u2_l = {1,0,0,1,-1};
    SK_l *u2 = nist.KeyGen(u2_l);

    nist.Encrypt();
    
    nist.Decrypt(u1_l,u1);
    nist.Decrypt(u2_l,u2);

    nist.clear();
    clear_SKl(u1);
    clear_SKl(u2);
    delete u1;
    delete u2;
    pairing_clear(pairing);
    return 0;
}