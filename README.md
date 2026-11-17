# vps-relay-setup

GitHub Actions собирает четыре статических Linux-бинарника при push в `main` или ручном запуске workflow **Linux builds**. Файлы доступны в артефакте `relay-tui-linux`; `dist/` не хранится в Git.

Для автопубликации:

1. Создайте проект Cloudflare Pages с Direct Upload и production-веткой `main`.
2. В GitHub → Settings → Secrets and variables → Actions добавьте секреты `CLOUDFLARE_ACCOUNT_ID` и `CLOUDFLARE_API_TOKEN` (право Account / Cloudflare Pages / Edit). Если проект называется не `relay-vps-setup`, задайте переменную `CLOUDFLARE_PAGES_PROJECT`.
3. Сверьте URL проекта с `base` в `install.sh`. Если адрес отличается, обновите его. Запустите workflow из `main`.

Pages публикует `install.sh`, `SHA256SUMS` и бинарники в корне сайта. Установщик скачивает файлы оттуда без доступа к GitHub.
