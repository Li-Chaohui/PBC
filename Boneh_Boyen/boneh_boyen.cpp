#include "../my.h"
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

pairing_t pairing;

class User{
    element_t x,y;//sk
public:
    element_t P,U,V;//pk
    element_t m;//消息
    element_t W,r;//签名
    void Stepup(){
        element_init_G1(P,pairing);
        element_init_Zr(x,pairing);
        element_init_Zr(y,pairing);

        element_init_G1(U,pairing);
        element_init_G1(V,pairing);

        element_random(x);
        element_random(y);

        element_mul_zn(U,P,x);
        element_mul_zn(V,P,y);
    }
    void Encrypt(){
        element_t temp_Zr1,temp_Zr2;
        element_init_Zr(r,pairing);
        element_init_Zr(m,pairing);
        element_init_G1(W,pairing);
        element_random(r);
        element_from_hash(m,(void*)"niao",4);

        //计算W
        element_init_Zr(temp_Zr1,pairing);
        element_init_Zr(temp_Zr2,pairing);
        element_add(temp_Zr1,x,m);
        element_mul(temp_Zr2,r,y);
        element_add(temp_Zr1,temp_Zr1,temp_Zr2);
        element_invert(temp_Zr1,temp_Zr1);
        element_mul_zn(W,P,temp_Zr1);

        element_clear(temp_Zr1);
        element_clear(temp_Zr2);
    }
    void Decrypt(){
        element_t temp_GT1,temp_GT2;
        element_t temp_G11,temp_G12;

        element_init_GT(temp_GT1,pairing);
        element_init_GT(temp_GT2,pairing);

        element_init_G1(temp_G11,pairing);
        element_init_G1(temp_G12,pairing);

        element_mul_zn(temp_G11,P,m);
        element_mul_zn(temp_G12,V,r);
        element_add(temp_G11,temp_G11,temp_G12);

        pairing_apply(temp_GT1,temp_G11,W,pairing);
        pairing_apply(temp_GT2,P,P,pairing);

        if(element_cmp(temp_GT1,temp_GT2) == 0){
            cout<<"验证成功！"<<endl;
        }
        else{
            cout<<"验证失败"<<endl;
        }

        element_clear(temp_G11);
        element_clear(temp_G12);
        element_clear(temp_GT1);
        element_clear(temp_GT2);
    }
    void clear(){
        element_clear(x);
        element_clear(y);
        element_clear(P);
        element_clear(U);
        element_clear(V);
        element_clear(m);
        element_clear(W);
        element_clear(r);
    }
};

int main(int argc,char **argv){
    pbc_demo_pairing_init(pairing,argc,argv);

    User u;
    {
        Timer t;
        u.Stepup();
        cout<<"系统建立耗时"<<t.elapsed()<<"ms"<<endl; 
    }

    {
        Timer t;
        u.Encrypt();
        cout<<"加密耗时"<<t.elapsed()<<"ms"<<endl;
    }

    {
        Timer t;
        u.Decrypt();
        cout<<"验证耗时"<<t.elapsed()<<"ms"<<endl;
    }

    u.clear();

    return 0;
}