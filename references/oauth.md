# OAuth 2.0 и OpenID Connect

## Суть
OAuth выдаёт приложению доступ к ресурсам пользователя у стороннего сервиса, а
OpenID Connect поверх него сообщает, кто пользователь. Протокол гибкий и многое
оставляет на усмотрение реализации, поэтому ошибки в клиенте (нашем приложении)
и в сервере авторизации приводят к входу под чужой учёткой, привязке чужого
профиля, утечке кода или токена.

## Где появляется в коде
- Колбэк `/auth/callback` не сверяет `state` с сохранённым в сессии.
- Нет PKCE (`code_challenge`/`code_verifier`) или используется implicit flow.
- Личность берётся из тела запроса фронтенда («вот email и токен»), а не из
  проверенного `id_token`/ответа `userinfo`, полученного сервером.
- `id_token` декодируется без проверки подписи, `iss`, `aud`, `exp`, `nonce`.
- Учётка сопоставляется по email без проверки `email_verified`, или по email вместо
  стабильного `sub` + `iss`.
- `redirect_uri` или адрес возврата после входа (`next=`) берётся из запроса.
- Токены провайдера пишутся в логи, кладутся в URL, отдаются во фронт.

```python
# плохо (authlib/httpx): state не проверяется, личность из формы
@app.post("/auth/finish")
async def finish(email: str = Form(...), access_token: str = Form(...)):
    return login_as(email)

# хорошо: authlib сам сверяет state и nonce, если пользоваться его методами
@app.get("/auth/callback")
async def callback(request: Request):
    token = await oauth.google.authorize_access_token(request)  # state, PKCE, id_token
    info = token["userinfo"]                                   # подпись/iss/aud/nonce проверены
    if not info.get("email_verified") or info.get("hd") not in ALLOWED:
        raise HTTPException(403)
    user = await upsert_by_sub(info["iss"], info["sub"], info["email"])
    request.session.clear(); request.session["uid"] = user.id   # новая сессия
    return RedirectResponse(safe_next(request.session.pop("next", "/")))
```

Node (`openid-client`, `passport`): `client.callback(redirectUri, params, {state, nonce,
code_verifier})` — все три должны передаваться; `passport` с `state: true`.

## Как искать
```
rg -n 'authorize_redirect|authorize_access_token|fetch_token|create_authorization_url' app/
rg -n 'state|nonce|code_verifier|code_challenge' app/ | rg -iv test
rg -n 'response_type.*token|implicit' app/
rg -n 'jwt\.decode\(.*verify_signature.*False|options=\{.verify' app/
rg -n 'redirect_uri|next=|return_to|RedirectResponse\(' app/
rg -n 'email_verified|hd|"sub"|\[.sub.\]' app/
rg -n 'userinfo|id_token' app/
```
Вопросы ревьюера:
- Где генерируется `state`, где сохраняется (в сессии этого браузера?), где
  сравнивается и удаляется после использования?
- Используется ли PKCE? Каким методом (`S256`)?
- Откуда сервер берёт личность пользователя — из проверенного ответа провайдера или
  из запроса клиента?
- Как учётка связывается с внешним профилем: `iss`+`sub` или email? Проверен ли
  `email_verified`? Ограничение домена — на сервере?
- Куда ведёт редирект после входа и можно ли его подменить?
- Можно ли привязать внешний профиль к уже вошедшей учётке, и защищено ли это `state`?

## Обходы, о которых забывают
- **Нет или слабый `state`.** Злоумышленник начинает вход у себя, останавливается
  перед колбэком и подсовывает жертве ссылку с собственным кодом: жертва оказывается
  в учётке злоумышленника (login CSRF) или — при функции «привязать соцсеть» — к
  учётке жертвы привязывается профиль злоумышленника. `state`, не связанный с сессией
  браузера, или одинаковый для всех, не помогает.
- **Implicit flow с доверием фронту.** Токен приходит в браузер, фронт отправляет на
  сервер «email + токен», сервер не сверяет, кому выдан токен, — достаточно поменять
  email.
- **Слабая проверка `redirect_uri` у провайдера.** Сравнение по префиксу, по домену,
  с поддоменами, нормализация путей, дубли параметров, разное толкование `localhost`
  — и код/токен уходит на чужой адрес. Даже точное совпадение домена не спасает,
  если на этом домене есть открытый редирект или XSS: код утечёт оттуда.
- **Утечка кода через `Referer`** со страницы колбэка, если она грузит сторонние
  скрипты/картинки, или через вывод кода в инлайн-JS.
- **Расширение scope** при обмене кода или в запросе `userinfo`, если сервер не
  сверяет выданный scope с запрошенным изначально.
- **Неподтверждённая почта у провайдера.** Если провайдер позволяет завести профиль
  с чужим email без подтверждения, а клиент сопоставляет учётки по email — вход
  под жертвой.
- **`id_token` без проверки.** Подпись не проверяется, `aud` не сверяется (токен,
  выданный другому приложению, подходит и нам), `nonce` не проверяется (повтор).
  Все атаки на JWT из `jwt.md` применимы.
- **OIDC-сервер:** открытая динамическая регистрация клиентов позволяет задать
  адреса (`logo_uri`, `jwks_uri`, `redirect_uris`), которые сервер потом сам
  скачивает — SSRF; параметры, переданные «по ссылке» (`request_uri`), могут
  миновать проверки, которые применяются к обычной строке запроса.
- **Mix-up** при нескольких провайдерах: ответ одного принимается как ответ другого,
  если не проверяется `iss`.

## Как исправить правильно
- Authorization Code + PKCE (`S256`) для всех клиентов; implicit и password grant —
  не использовать.
- `state` (и `nonce` для OIDC) — криптослучайные, одноразовые, хранятся в серверной
  сессии этого браузера; сверка до обмена кода. Готовые библиотеки (authlib,
  openid-client) делают это сами — не обходить их ручным разбором параметров.
- `redirect_uri` — фиксированный из конфига, точное совпадение; передаётся и в
  запрос авторизации, и при обмене кода.
- Личность — только из `id_token`, проверенного на сервере (подпись по JWKS
  провайдера, `iss`, `aud`=наш `client_id`, `exp`, `nonce`), или из `userinfo`,
  запрошенного сервером. Ключ учётки — `iss`+`sub`; email — только при
  `email_verified=true`.
- Ограничение по домену компании — на сервере (`hd` и домен проверенной почты).
- После входа — новая сессия; адрес возврата — только относительный путь из
  allowlist.
- Токены провайдера — только на сервере, не в логах и URL; refresh-токены
  шифровать/ротировать; минимальные scope.
- Страница колбэка — без сторонних ресурсов, `Referrer-Policy: no-referrer`.

## Ложные срабатывания
- Отсутствие ручной проверки `state`, когда вызов идёт через `authorize_access_token`
  authlib/`callback` openid-client — проверка внутри (убедиться, что сессия та же).
- `redirect_uri` собирается через `url_for`, но хост жёстко задан прокси/конфигом
  (проверить `--proxy-headers` и доверенные прокси).
- Server-to-server client credentials — там нет пользователя и `state` не нужен.

## Источники
- PortSwigger Web Security Academy (только ссылки):
  https://portswigger.net/web-security/oauth ,
  https://portswigger.net/web-security/oauth/grant-types ,
  https://portswigger.net/web-security/oauth/openid ,
  https://portswigger.net/web-security/oauth/preventing
- OWASP OAuth 2.0 Protocol Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html

Рекомендации «Authorization Code + PKCE для всех клиентов», «не использовать implicit
и password grant», «проверять `iss` при нескольких серверах», «минимальные scope и
ограничение audience» адаптированы из шпаргалки OWASP (CC BY-SA 4.0). Описание
обходов — своими словами по мотивам Академии PortSwigger, без копирования.
