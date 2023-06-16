Реализация протокола проверки подлинности Kerberos

Порядок запуска:

1) .\bin\Debug\net6.0\Kerberos.exe kdc inputKeyTgs.txt clientDb.txt

2) .\bin\Debug\net6.0\Kerberos.exe tgs inputKeyTgs.txt serverDb.txt

3) .\bin\Debug\net6.0\Kerberos.exe server inputKeyTgsSs.txt

4) .\bin\Debug\net6.0\Kerberos.exe client inputKeyClient.txt output.txt