#!/usr/bin/env python3
"""
Şifre Hash'leme Aracı
Kullanıcı şifrelerini SHA-256 ile hash'ler
"""

import hashlib
import getpass

def hash_password(password):
    """Şifreyi SHA-256 ile hash'ler"""
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    print("🔐 Şifre Hash'leme Aracı")
    print("=" * 30)
    
    while True:
        print("\n1. Şifre hash'le")
        print("2. Şifre doğrula")
        print("3. Çıkış")
        
        choice = input("\nSeçiminiz (1-3): ").strip()
        
        if choice == "1":
            print("\n--- Şifre Hash'leme ---")
            username = input("Kullanıcı adı: ").strip()
            password = getpass.getpass("Şifre: ")
            
            if username and password:
                hashed = hash_password(password)
                print(f"\n✅ Hash oluşturuldu!")
                print(f"Kullanıcı: {username}")
                print(f"Hash: {hashed}")
                print(f"\nsecrets.toml'a eklenecek satır:")
                print(f'"{username}" = "{hashed}"')
            else:
                print("❌ Kullanıcı adı ve şifre gerekli!")
        
        elif choice == "2":
            print("\n--- Şifre Doğrulama ---")
            password = getpass.getpass("Test edilecek şifre: ")
            hash_to_check = input("Hash değeri: ").strip()
            
            if hash_password(password) == hash_to_check:
                print("✅ Şifre doğru!")
            else:
                print("❌ Şifre yanlış!")
        
        elif choice == "3":
            print("Çıkış yapılıyor...")
            break
        
        else:
            print("❌ Geçersiz seçim!")

if __name__ == "__main__":
    main()