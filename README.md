# auth microservice

В этой директории также должны находиться файлы

.db.env
```
POSTGRES_USER=%your_username%
POSTGRES_PASSWORD=%your_password%
POSTGRES_DB=%your_db%
```


.rtoken.salt.env
```
REFRESH_TOKEN_HASH_SALT="BCRYPT SALT HERRE"
```
соль представляет из себя длинную случайную строку
