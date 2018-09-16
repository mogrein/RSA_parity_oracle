# RSA_parity_oracle
## Зависимости
Установите зависимости:
* rust-stable - [тык](https://www.rust-lang.org/ru-RU/install.html)
* openssl-devel для rust-openssl - [тык](https://github.com/sfackler/rust-openssl)

## Сборка

```
cargo build --release
```

## Запуск
Строка с секретом берётся из переменной окружения SECRET:

```
SECRET="some text" cargo run --release
```
