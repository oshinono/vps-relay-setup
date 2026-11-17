# vps-relay-setup

При push в `main` GitHub Actions публикует четыре статических Linux-бинарника и `SHA256SUMS` в [GitHub Releases](https://github.com/oshinono/vps-relay-setup/releases/latest). Используется встроенный `GITHUB_TOKEN`. Для скачивания без токена репозиторий должен быть публичным.

На Cloudflare Pages опубликуйте только `install.sh` в корне сайта. Секреты Cloudflare в GitHub не нужны. Скрипт выбирает архитектуру, скачивает бинарник из последнего релиза и проверяет SHA-256.
