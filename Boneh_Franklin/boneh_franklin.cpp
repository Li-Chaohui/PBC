/*
	在双线性配对环境下实现Boneh-Franklin加密方案。
	注意：
	（1）该方案的加解密过程需要执行异或运算。PBC库并不支持该运算，考虑到该运算的执行速度快，所消耗较其他运算
可以忽略。因此，在《基于配对的密码学》一书中，直接忽略了此项运算。
	（2）PBC库同样不支持散列函数，但是提供了模拟函数element_from_hash(element_t e, void * data, int len)。其中，
第一个参数用于存储运算结果，第二个参数是任意长度的字符串，第三个参数是该字符串的长度。Boneh-Franklin方案使用了
两个散列函数。第一个函数将任意输入映射到群GT。第二个函数将任意输入映射为长度为lm的串。这两个函数都是使用
函数element_from_hash进行模拟。区别在于，需要将第一个散列函数的输出初始化为群GT上的元素，将第二个散列函数的
输出初始化为域Zp上的元素。
*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

/////////////////////////////全局变量
pairing_t pairing;//定义对环境变量
element_t P;//基点G
element_t P_pub;//公钥
element_t s;//主密钥
element_t Qu;//用户公钥
element_t Su;//用户解密私钥
element_t m;//原始消息
element_t m_recovered;//解密恢复得到的消息
element_t V,W;//密文包含的两个元素

/*
	功能：产生主密钥和系统公开参数
	步骤：
	（1）变量初始化。
	（2）为变量赋随机值。
	（3）产生主密钥和公开元素。
	（4）输出主密钥和公开元素。
*/
void Setup(){
	element_init_G1(P,pairing);
	element_init_G1(P_pub,pairing);
	element_init_Zr(s,pairing);
	element_random(s);
	element_random(P);
	element_mul_zn(P_pub,P,s);
	printf("\n Output of the Setup phase:\n");
	element_printf("s=%B\n",s);
	element_printf("P=%B\n",P);
	element_printf("P_pub=%B\n",P_pub);
}			  
			  
			  
/*
	功能：提取用户的解密私钥和公钥
	步骤：
	（1）变量初始化。
	（2）产生用户的公钥和解密私钥。
	（3）输出用户的公钥与私钥。
*/
void Extract(){
	element_init_G1(Qu,pairing);
	element_init_G1(Su,pairing);
	element_from_hash(Qu,(void*)"User's identity",15);
	element_mul_zn(Su,Qu,s);
	printf("\n Output of the Extract phase:\n");
	element_printf("Qu=%B\n",Qu);
	element_printf("Su=%B\n",Su);
}
/*
	功能：产生密文
	步骤：
	（1）变量初始化。
	（2）产生密文。
	（3）输出密文。
*/
void Encrypt(){
	element_t r;
	element_t temp_GT;
	element_init_Zr(r,pairing);
	element_init_G1(V,pairing);
	element_init_GT(W,pairing);
	element_init_GT(temp_GT,pairing);

	element_random(r);
	element_mul_zn(V,P,r);
	pairing_apply(temp_GT,P_pub,Qu,pairing);
	element_pow_zn(W,temp_GT,r);
	printf("\n Output of the Encrypt phase:\n");
	element_printf("V=%B\n",V);
	element_printf("W=%B\n",W);
}
/*
	功能：输出解密结果
	（1）变量初始化。
	（2）模拟解密过程。
*/
void Decrypt(){
	element_t temp_GT;
	element_t hash_value;
	element_init_GT(temp_GT,pairing);
	element_init_Zr(hash_value,pairing);
	pairing_apply(temp_GT,V,Su,pairing);
	element_from_hash(hash_value,(void*)"Input of hash function2",23);
	
}


/*
	功能：对Boneh-Franklin方案的执行过程进行仿真
	（1）初始化类型为A的配对环境。
	（2）依次执行Boneh-Franklin加密方案的系统建立、密钥提取、加密和解密过程。
	（3）输出Boneh-Franklin加密方案的系统建立、密钥提取、加密和解密过程的执行时间。
*/
int main(int argc, char **argv){
	
	//初始化为类型A的配对环境
	pbc_demo_pairing_init(pairing, argc, argv);
	
	Setup();

	Extract();
	
	Encrypt();

	Decrypt();

	//释放对环境变量 
	pairing_clear(pairing);
	return 0;
}



