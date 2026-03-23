import sys
import redis

class RedisUtils:
    def __init__(self, host='localhost', port=6379, db=0):
        self.redis = redis.Redis(host=host, port=port, db=db)

    def set(self, key, value, ex = 18000):
        self.redis.set(key, value, ex=ex)

    def get(self, key) -> str:
        value = self.redis.get(key)
        if value is not None:
            return value.decode('utf-8')
        return '0'

    def delete(self, key):
        self.redis.delete(key)


if __name__ == "__main__":
    r_util = RedisUtils()
    r_util.set('test_key', 'test_value')
    print(r_util.get('test_key'))
    r_util.delete('test_key')
    print(r_util.get('test_key'))