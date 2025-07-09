# Wymagania
- go 1.24

# Kompilacja
- z poziomu pliku go.mod należy wykonać podaną operacje: ```go build -o main src/main/main.go```

# Dodatkowe informacje
- pliki, które chcemy udostępnić powinny znajdować się w folderze `root/` znajdującym
    się na tym samym poziomie co plik wykonywalny. Załączony został przykładowy plik.
- pliki, które pobierzemy zostaną zapisane w foldrze `Download/` znajdującym
    się na tym samym poziomie co plik wykonywalny, będą one podzielone względem nazwy
    zucha od którego pobraliśmy dany plik

# Uruchamianie
- powstały plik programu ma kilka dostępnych opcji:
    - `nickname` - nick pod jakim chcemy się połączyć
    - `log-to-file` - flaga binarna. Gdy użyta, wszystkie logi zostaną zapisane do pliku `app.log`
    - `log-level` - najniższy poziom logów, który ma zostać uwzględniony
- polecamy użyć opcji `log-to-file`, lub przy uruchamianiu przekierować stderr, tak,
    aby logi nie zakłucały korzystania z interfejsu w terminalu
- przykładowe uruchomienie ```./main --log-level="INFO" --nickname="MłodyG" 2>/dev/pts/2```