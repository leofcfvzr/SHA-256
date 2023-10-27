# SHA-256
Кибербезопасность - это широкий и сложный область, но вот пример простого кода на Python для организации базовой защиты пароля.  
Этот пример демонстрирует, как можно использовать хеширование паролей (в данном случае с использованием SHA-256) для защиты паролей пользователей. Ваша задача будет заключаться в разработке более сложных и современных методов для защиты информации и сетевой безопасности.
import hashlib

def generate_password_hash(password):
    """Генерирует хеш пароля"""
    salt = "somesalt"   # Соль для усиления безопасности
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return password_hash

def check_password(password, password_hash):
    """Проверяет, соответствует ли пароль его хешу"""
    salt = "somesalt"
    entered_password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return password_hash == entered_password_hash

password = input("Введите пароль: ")
password_hash = generate_password_hash(password)

print("Хеш пароля:", password_hash)

entered_password = input("Введите пароль для проверки: ")
if check_password(entered_password, password_hash):
    print("Введенный пароль верный")
else:
    print("Введенный пароль неверный")
