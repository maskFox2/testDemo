import random
from sympy import nextprime

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from base64 import b64encode, b64decode


# 生成随机素数
def generate_random_prime(bits):
    return nextprime(random.getrandbits(bits), bits)


# 生成多个素数
def generate_multiple_primes(num_primes, bits):
    primes = []
    for _ in range(num_primes):
        primes.append(generate_random_prime(bits))
    return primes


# 使用多素数生成RSA密钥对
def generate_multi_prime_rsa_keypair(num_primes, bits):
    primes = generate_multiple_primes(num_primes, bits)
    n = 1
    totient = 1
    for prime in primes:
        n *= prime
        totient *= (prime - 1)

        # 选择e，使e与totient互质
    e = 65537  # 通常使用65537作为公钥指数  
    # 确保e与totient互质  
    gcd = 1
    for prime in primes:
        gcd = (gcd * (prime - 1)) // gcd
    assert gcd == 1, "e is not coprime with totient"

    # 计算私钥d  
    d = (totient ** -1) % e

    # 创建RSA对象  
    key = RSA.construct((long_to_bytes(e), long_to_bytes(d), long_to_bytes(n)))

    # 编码公钥和私钥为Base64  
    public_key_b64 = b64encode(key.publickey().export_key()).decode('utf-8')
    private_key_b64 = b64encode(key.export_key()).decode('utf-8')

    return public_key_b64, private_key_b64


# 示例：生成3个素数，每个素数为256位
public_key_b64, private_key_b64 = generate_multi_prime_rsa_keypair(3, 256)

print("Public Key (Base64):")
print(public_key_b64)
print("\nPrivate Key (Base64):")
print(private_key_b64)