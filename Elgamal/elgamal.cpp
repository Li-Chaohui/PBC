#include "../my.h"
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

using namespace std;

pairing_t pairing;//

void init(pairing_t pairing,int argc,char **argv){
    pbc_demo_pairing_init(pairing,argc,argv);
}

class Msk{

private:

    element_t g,pk,sk,m,m_re,c1,c2;
    /**
     * 产生密钥
    */
    void Keygen(){
        element_init_G1(g,pairing);
        element_init_G1(pk,pairing);
        element_init_Zr(sk,pairing);
        element_random(g);
        element_random(sk);
        element_mul_zn(pk,g,sk);
    }

    void init(){
        Keygen();
    }

public:
    Msk(){
        init();
    }

    /**
     * 加密
    */
    void Encrypt(){
        element_t temp_g,k;//k为随机加密数
        element_init_G1(m,pairing);
        element_init_G1(c1,pairing);
        element_init_G1(c2,pairing);
        element_init_G1(temp_g,pairing);
        element_init_Zr(k,pairing);

        element_random(k);
        element_random(m);
        element_mul_zn(c1,g,k);
        element_mul_zn(temp_g,pk,k);
        element_add(c2,m,temp_g);

        element_clear(k);
        element_clear(temp_g);
    }

    /**
     * 解密
    */
    void Decrypt(){
        element_t temp_g;
        element_init_G1(temp_g,pairing);
        element_init_G1(m_re,pairing);
        element_mul_zn(temp_g,c1,sk);
        element_sub(m_re,c2,temp_g);
        if(element_cmp(m,m_re)==0){
            cout<<"成功！"<<endl;
        }
        element_clear(temp_g);
    }

    void clear(){
        //element_t g,pk,sk,m,m_re,c1,c2;
        element_clear(g);
        element_clear(pk);
        element_clear(sk);
        element_clear(m);
        element_clear(m_re);
        element_clear(c1);
        element_clear(c2);
    }

};

int main(int argc,char **argv){

    init(pairing,argc,argv);

    Msk m;
    m.Encrypt();
    m.Decrypt();
    m.clear();
    return 0;
}