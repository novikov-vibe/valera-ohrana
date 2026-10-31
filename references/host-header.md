# Атаки через заголовок Host

## Суть
`Host` (и его «заместители» `X-Forwarded-Host`, `Forwarded`, `X-Host` и др.)
полностью контролирует клиент. Приложения часто строят из него абсолютные
ссылки — в письмах сброса пароля, приглашениях, OAuth `redirect_uri`, ссылках в
мессенджер — а прокси маршрутизируют по нему запросы. Без проверки это даёт
отравленные ссылки сброса (кража токена), отравление кэша, SSRF через
маршрутизацию прокси и доступ к внутренним виртуальным хостам.

## Где появляется в коде
- Сборка ссылок из запроса: `request.url_for(...)`, `request.base_url`,
  `request.url.netloc`, `request.headers["host"]`, `str(request.url)` — в
  письмах, личных сообщениях бота (Mattermost), приглашениях, ссылках «открыть
  созвон», OAuth `redirect_uri`.
- uvicorn `--proxy-headers` c `--forwarded-allow-ips="*"` (или
  `FORWARDED_ALLOW_IPS=*`): `X-Forwarded-Proto`/`For` начинает принимать от кого
  угодно; Starlette `ProxyHeadersMiddleware`, свой middleware, читающий
  `X-Forwarded-Host`.
- Проверки доступа по хосту: «если Host == admin.local — пустить».
- nginx/Caddy: `proxy_set_header Host $http_host` (пробрасывает клиентский
  заголовок как есть, вместе с портом), `server_name _` / default server,
  проксирующий в приложение, `proxy_pass http://$host...` (маршрутизация по
  клиентскому Host = SSRF).
- Отсутствие `TrustedHostMiddleware` / `ALLOWED_HOSTS`.

Плохо:
```python
link = f"{request.base_url}reset?token={token}"          # Host от клиента
# или
link = str(request.url_for("reset_password")) + f"?token={token}"
```
Хорошо:
```python
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")         # фиксируется при деплое
link = f"{PUBLIC_URL}/reset?{urlencode({'token': token})}"
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["app.example.ru"])
# uvicorn ... --proxy-headers --forwarded-allow-ips=127.0.0.1
```

## Как искать
```
rg -n "base_url|url_for\(|request\.url\b|url\.netloc|headers\[.host.\]|headers\.get\(.host" app/
rg -n -i "x-forwarded-host|x-forwarded-server|x-host|x-original-url|x-rewrite-url|forwarded" app/ deploy/
rg -n "forwarded-allow-ips|FORWARDED_ALLOW_IPS|proxy-headers|ProxyHeadersMiddleware|TrustedHostMiddleware"
rg -n "redirect_uri|reset|invite|magic.?link|verify.?email" app/ -i
rg -n "proxy_set_header Host|server_name|default_server|proxy_pass .*\$host|\$http_host" deploy/ *.conf Caddyfile
```
Вопросы ревьюера:
- Каждая абсолютная ссылка, уходящая наружу (письмо, чат, OAuth), строится из
  конфигурации или из запроса?
- Что делает приложение/прокси с неизвестным `Host`? Отвечает ли default
  server приложением?
- От каких IP uvicorn доверяет `X-Forwarded-*`? Перезаписывает ли их прокси или
  дописывает к клиентским?
- Маршрутизирует ли прокси по `Host` к переменному апстриму?

## Обходы, о которых забывают
- **Заголовки-заместители.** Проверили `Host`, а фреймворк, middleware или
  библиотека подставляют значение из `X-Forwarded-Host` или `Forwarded`; часто
  это включено по умолчанию в сторонних компонентах, и автор кода о нём не знает.
- **Порт.** Валидатор сравнивает только имя и игнорирует порт, а ссылка
  строится из полного значения — в «порт» можно поместить что угодно.
- **Сравнение по суффиксу/подстроке.** `endswith("example.ru")` пропускает
  зарегистрированный злоумышленником домен с тем же окончанием; подстрочное
  совпадение — ещё хуже; захваченный поддомен тоже «свой».
- **Двойной Host, абсолютный URL в строке запроса, «завёрнутый» (с отступом)
  заголовок.** Фронт и бэк выбирают разные значения: один маршрутизирует по
  правильному, другой строит ссылку из подставного.
- **Состояние соединения.** Прокси проверяет только первый запрос на keep-alive
  соединении и дальше считает хост тем же — второй запрос с другим Host
  проходит.
- **«Ссылку получит жертва, токен на её почте — значит, безопасно».** Жертва
  (или почтовый сканер, превью ссылок в мессенджере) переходит по ссылке, и
  токен уходит на хост злоумышленника; иногда даже не нужен клик.
- **Внутренние виртуальные хосты** на том же IP, что и публичный сайт, доступны
  простым перебором имён в Host.
- **Host как обычный ввод.** Он попадает в логи, SQL, шаблоны — классические
  инъекции через него тоже возможны.

## Как исправить правильно
1. Все внешние ссылки — из `PUBLIC_URL` (env/конфиг), никогда из запроса; только
   https. Относительные ссылки там, где это возможно.
2. `TrustedHostMiddleware` с точным списком хостов; на прокси — default server,
   отвечающий 444/400, и `server_name` с точным доменом.
3. `--forwarded-allow-ips` — только IP своего прокси; прокси выставляет
   `X-Forwarded-*` своими значениями (`$host`, `$scheme`, `$remote_addr`), а не
   пробрасывает клиентские. Не включать поддержку `X-Forwarded-Host`, если не
   нужна.
4. Прокси не маршрутизирует по клиентскому Host на произвольные апстримы;
   внутренние vhost — на отдельном интерфейсе.
5. Токены в ссылках — одноразовые, с коротким сроком, привязаны к пользователю;
   не логировать.

## Ложные срабатывания
- `request.url_for()` для относительного пути внутри шаблона страницы (не уходит
  наружу) при включённом `TrustedHostMiddleware`.
- Чтение `Host` только для логов/метрик.
- `X-Forwarded-*`, которым доверяют только от `127.0.0.1`, при прокси, который
  их перезаписывает.

## Источники
- PortSwigger Academy — HTTP Host header attacks: https://portswigger.net/web-security/host-header
- Exploiting: https://portswigger.net/web-security/host-header/exploiting
- Password reset poisoning: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
- PortSwigger Research — Cracking the lens (маршрутизация по Host):
  https://portswigger.net/research
  (материалы PortSwigger только прочитаны; текст выше написан самостоятельно)
- OWASP Forgot Password Cheat Sheet (раздел URL Tokens: не строить ссылку из
  Host, домен жёстко задан или сверен со списком, только HTTPS):
  https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
  — адаптировано, CC BY-SA 4.0.
- OWASP WSTG — Testing for Host Header Injection:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection
  — использовано как справка (CC BY-SA 4.0).
