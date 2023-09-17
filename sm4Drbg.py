import secrets 
import time 
from gmssl.sm4 import CryptSM4,SM4_ENCRYPT
class SM4_RNG:
    def __init__(self,personalization_string :bytes = b"",nonce:bytes = b""):
        # 分组密码算法所使用的密钥长度
        self.keylen= 16 # 128比特
        # 重播种计数器，表明自初始化或者重播种期间获得新的熵输入依赖，请求随机数生成的次数
        self.reseed_counter = 0
        # 重播种计数器阈值，在重播种之前能够产生随机数的最大请求次数
        # level 1 2^20次
        # level 2 2^10次
        self.reseed_interval_in_counter = 1<<30
        # 重播种时间阈值，距离上一次重播种的最大时间间隔，单位 秒
        # level 1 600s
        # level 2 60s
        self.reseed_interval_in_time = 6000
         # 最小的熵输入长度
        self.min_entropy_input_length = 32 # 256比特
        # 最大的熵输入长度
        self.max_ectropy_input_length = 1<<35 - 1 # 2^35比特
        self.seedlen = 32 # 256比特
        # 输出函数输出的比特长度
        self.outlen = 16 # 128比特
        # 分组密码算法的输出分组的长度
        self.blocklen = 16 # 128比特
        # 种子材料
        self.seed_material = ""
        self.sm4 = CryptSM4()
        self.SM4_RNG_Instantiate(personalization_string,nonce)
    def SM4_RNG_Instantiate(self,personalization_string :bytes = b"",nonce:bytes = b""):
        self.min_entropy = self.min_entropy_input_length
        self.entropy_input = secrets.token_bytes(self.min_entropy)
        self.seed_material = self.entropy_input + nonce + personalization_string
        self.seed_material = self.SM4_df(self.seed_material,self.seedlen)
        self.Key = b"\x00" * self.keylen
        self.V = b"\x00" * self.blocklen
        self.SM4_RNG_Update(self.seed_material,self.Key,self.V)
        self.reseed_counter = 1
        self.last_reseed_time = int(time.time())
        
    def SM4_RNG_Update(self,seed_material,Key,V):
        temp = b""
        self.sm4.set_key(Key,SM4_ENCRYPT)
        while(len(temp) < self.seedlen):
            V = (int.from_bytes(V,"big") + 1) % (1<<self.blocklen)
            self.output_block = self.sm4.crypt_ecb(V.to_bytes(self.blocklen,"big"))
            temp = temp + self.output_block
        temp = temp[:self.seedlen]
        temp = int.from_bytes(temp,"big") ^ int.from_bytes(seed_material,"big")
        temp = temp.to_bytes(self.seedlen,"big")
        self.Key = temp[:self.keylen]
        self.V = temp[-self.blocklen:]
        
    def SM4_df(self,input_string:bytes,number_of_bits_to_return:int):
        L = len(input_string)
        N = number_of_bits_to_return
        S = L.to_bytes(4,"big") + N.to_bytes(4,"big") + input_string + b"\x80"
        while(len(S) % self.outlen != 0):
            S = S + b"\x00"
        temp = b""
        i = 0
        K = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F \
        \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"[:self.keylen]
        while len(temp)<self.keylen + self.outlen:
            IV = i.to_bytes(4,"big") + b"\x00" * (self.outlen - 4)
            temp = temp + self.CBC_MAC(K,(IV+S))
            i = i + 1
        K = temp[:self.keylen]
        X = temp[self.keylen+1:self.keylen+self.outlen]
        tmp = b"" 
        self.sm4.set_key(K,SM4_ENCRYPT)
        while len(tmp) < number_of_bits_to_return:
            X = self.sm4.crypt_ecb(X)
            tmp = tmp + X
        requested_bits = tmp[:number_of_bits_to_return]
        return requested_bits
    
    def CBC_MAC(self,Key,data_to_MAC):
        self.sm4.set_key(Key,SM4_ENCRYPT)
        chaining_value = b"\x00" * self.outlen
        n = len(data_to_MAC) / self.outlen
        for i in range(int(n)):
            input_block = int.from_bytes(chaining_value,"big") ^ int.from_bytes(data_to_MAC[i*self.outlen:(i+1)*self.outlen],"big")
            chaining_value = self.sm4.crypt_ecb(input_block.to_bytes(self.outlen,"big"))
            chaining_value = chaining_value[:self.outlen]
        output_block = chaining_value
        return output_block
    
    def SM4_RNG_Reseed(self,additional_input:bytes):
        self.min_entropy = self.min_entropy_input_length
        self.entropy_input = secrets.token_bytes(self.min_entropy)
        self.seed_material = self.entropy_input + additional_input
        self.seed_material = self.SM4_df(self.seed_material,self.seedlen)
        self.SM4_RNG_Update(self.seed_material,self.Key,self.V)
        self.reseed_counter = 1
        self.last_reseed_time = int(time.time())
        
    def SM4_RNG_Generate(self,requested_number_of_bits,additional_input:bytes=b""):
        length = int(requested_number_of_bits / 8)
        returned_bits = b""
        if self.reseed_counter > self.reseed_interval_in_counter or int(time.time()) - self.last_reseed_time > self.reseed_interval_in_time:
            self.SM4_RNG_Reseed(additional_input)
        if additional_input != b"":
            additional_input = self.SM4_df(additional_input,self.seedlen)
            self.SM4_RNG_Update(additional_input,self.Key,self.V)
        else: 
            additional_input = b"\x00" * self.seedlen
        self.sm4.set_key(self.Key,SM4_ENCRYPT)
        while(len(returned_bits) < length):
            self.V = int.from_bytes(self.V,"big") + 1 % (1<<self.blocklen)
            self.V = self.V.to_bytes(self.blocklen,"big")
            output_block =self.sm4.crypt_ecb(self.V)
            returned_bits = returned_bits + output_block
        self.SM4_RNG_Update(additional_input,self.Key,self.V)
        self.reseed_counter += 1
        return returned_bits[:length]
if __name__ == "__main__":
    sm4Drbg = SM4_RNG()
    with open("./randomData.txt","wb") as f:
        for i in range(1000):
            print(i)
            f.write(sm4Drbg.SM4_RNG_Generate(1000000))  
        f.close()   
