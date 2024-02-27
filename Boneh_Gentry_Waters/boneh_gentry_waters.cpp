#include "../my.h"
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

#define N 10

pairing_t pairing;

struct PK{
    element_t V,G;
    vector<element_t> Gi;
    PK():Gi(2*N+1){}
};

struct CT{
    element_t C0,C1;
};


class SP{
    CT ct;
    element_t msk,Gn_1,K;//主密钥，Gn+1，封装密钥
    vector<element_t> Di;//全体用户密钥
    vector<int> vaild;
    void Setup(){
        //1.定义双线性映射
        //2.生成基点和alpha
        element_t alpha;
        element_init_G1(pk.G,pairing);
        element_init_Zr(alpha,pairing);
        element_random(pk.G);
        element_random(alpha);
        //3.计算Gi
        element_t pow,temp_Zr;
        element_init_G1(Gn_1,pairing);
        element_init_Zr(pow,pairing);
        element_init_Zr(temp_Zr,pairing);
        for(int i = 1;i<=2*N;i++){
            element_set_si(pow,i);
            element_pow_zn(temp_Zr,alpha,pow);
            element_init_G1(pk.Gi[i],pairing);
            if(i!=N+1){
                element_mul_zn(pk.Gi[i],pk.G,temp_Zr);//2.计算Gi
            }
            else{
                element_mul_zn(Gn_1,pk.G,temp_Zr);
            }
        }
        //4.生成主密钥
        element_init_Zr(msk,pairing);
        element_init_G1(pk.V,pairing);
        element_random(msk);//初始化主密钥
        element_mul_zn(pk.V,pk.G,msk);//计算V
        //5.生成用户解密密钥
        for(int i = 1;i<=N;i++){
            element_init_G1(Di[i],pairing);
            element_mul_zn(Di[i],pk.Gi[i],msk);
        }
        
        element_clear(alpha);
        element_clear(pow);
        element_clear(temp_Zr);

    }

    

public:
    PK pk;
    
    SP():Di(N+1),vaild(N+1){
        for(int i = 1;i<=N;i++){
            if(i%2==0){
                vaild[i] = 1;
            }
            else{
                vaild[i] = 0;
            }
        }
        Setup();
    }

    void Encrypt(){
        //1.选取t生成封装密钥
        element_t t;
        element_init_Zr(t,pairing);
        element_init_GT(K,pairing);
        element_random(t);
        pairing_apply(K,Gn_1,pk.G,pairing);
        element_pow_zn(K,K,t);
        //2.产生密文
        element_init_G1(ct.C0,pairing);
        element_init_G1(ct.C1,pairing);
        
        element_mul_zn(ct.C0,pk.G,t);
        element_set(ct.C1,pk.V);
        for(int j = 1;j<=N;j++){
            if(vaild[j]==1){
                element_add(ct.C1,ct.C1,pk.Gi[N+1-j]);
            }
        }
        element_mul_zn(ct.C1,ct.C1,t);
    

        element_clear(t);
    }

    void Decrypt(int i){
        //1.判断是否为非法下标
        if(vaild[i] == 0){
            cout<<"非法下标"<<endl;
            return;
        }
        //2.计算K
        element_t temp_k,temp_GT1,temp_GT2,temp_G1;
        element_init_GT(temp_k,pairing);
        element_init_GT(temp_GT1,pairing);
        element_init_GT(temp_GT2,pairing);
        element_init_G1(temp_G1,pairing);
        //分子
        pairing_apply(temp_GT1,pk.Gi[i],ct.C1,pairing);
        //分母
        element_set(temp_G1,Di[i]);
        for(int j = 1;j<=N;j++){
            if(j!=i && vaild[j]==1){
                element_add(temp_G1,temp_G1,pk.Gi[N+1-j+i]);
            }
        }
        pairing_apply(temp_GT2,temp_G1,ct.C0,pairing);
        //最终计算的K
        element_div(temp_k,temp_GT1,temp_GT2);
        if(element_cmp(temp_k,K)==0){
            cout<<"解密成功！"<<endl;
        }
        else{
            cout<<"解密失败"<<endl;
        }

        element_clear(temp_G1);
        element_clear(temp_GT1);
        element_clear(temp_GT2);
        element_clear(temp_k);
    }

    void clear(){
        element_clear(ct.C0);
        element_clear(ct.C1);
        element_clear(msk);
        element_clear(Gn_1);
        element_clear(K);
        for(int i = 1;i<=N;i++){
            element_clear(Di[i]);
        }
        element_clear(pk.G);
        element_clear(pk.V);
        for(int i =1;i<=2*N;i++){
            element_clear(pk.Gi[i]);
        }
    }
};

int main(int argc,char** argv){
    pbc_demo_pairing_init(pairing,argc,argv);

    SP nist;
    nist.Encrypt();
    nist.Decrypt(2);
    nist.clear();

    return 0;
}