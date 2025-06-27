import redis

try:
    r = redis.Redis(host='77.91.86.135', port=5540, db=0)
    if r.ping():
        print("Подключение к Redis успешно!")
    else:
        print("Не удалось подключиться к Redis.")
except redis.exceptions.ConnectionError as e:
    print(f"Ошибка подключения к Redis: {e}")