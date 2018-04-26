# Первое домашее задание на blockchain-dev

Уровень - Easy (обязательное)
1. Зарегистрироваться в github и изучить основные функции. 
2. Посчитать хеш-функцию от данных и подписать данные. 
Уровень Medium (по желанию).
Реализовать ЭЦП. Реализовать асимметричное шифрование (приватный и публичный ключ) - зашифровать и расшифровать текст.

***
В папке hashe расположен скрипт с домашним заданием
### Основные функции
1. Генерация публичного и приватного ключа. Вызов срипта с параметром **newkeys** сгенирурует пару публичный/приватный ключ и запишет его в файл. Название файла можно менять в конфиге.
Например:
``` 
 node hash newkeys
```
Выведет в консоль сообщение
```
  publicKey: 02ba998b8548336d843703a0f8ed35945323c5765ae22204b8937210684a0f6f3e
	secretKey: 6dc5dc834588e128274fa36cfb3d4d4d0e7173e2aebc2b1e882c5d6f6c147ffa 
	keys were written to keys.json
```
В котором указан приватный и публичный ключ. 

2. Генерация ЭЦП. Вызов скрипта с параметром ***sign***, запросит у пользователя ввести строку с текстом, затем сформирует ему цифровую подпись, на основе ранее сгенерированного приватного ключа. 
```
node hash sign
```
Запросит строку и выведет сообщение: 
```
Please, paste you message: Hello World
You message: Hello World;
sha256 hash: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e;
You digital sign: 2552a871397f141f9dbebc19462026af9d67b2f7a4af3419822dca5....;
```

3. Проверка ЭЦП сообшения. Вызов скрипта с параметром ***verify***, запросит у пользователя ввести строку с текстом, затем подпись и публичный ключ. Если ключ был заранее сгенерирован, пункт можно пропустить нажжав Enter. 
```
node hash verify
```
Запросит данные, выведет результаты проверки

```
Please, paste message: Hello World
Please, paste sig: 2552a871397f141f9dbebc19462026af9d67b2f7a4af3419822dca5....
Please, paste public key or push Enter to use previously generated key: 
Verified: true;
```
