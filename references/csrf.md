# Cross-site request forgery (CSRF)

## Суть
Чужой сайт заставляет браузер жертвы отправить изменяющий запрос на наш сервис,
и браузер сам прикладывает cookie сессии. Сервер видит «настоящего» пользователя
и выполняет действие, которого тот не хотел. Нужны три условия: есть ценное
действие, сессия держится только на автоматически отправляемых cookie, а все
параметры запроса угадываемы. Ломаем хотя бы одно — атаки нет.

## Где появляется в коде
**Изменяющие роуты без проверки происхождения.**
```python
# плохо: POST без токена/Origin, сессия только из cookie
@router.post("/calls/{id}/delete")
async def delete_call(id: int, user=Depends(auth.current_user)): ...

# хорошо: общая зависимость на все небезопасные методы
@router.post("/calls/{id}/delete", dependencies=[Depends(same_origin_only)])
```
**Побочный эффект на GET.** `@router.get("/logout")`, `/unsubscribe`,
`/tasks/{id}/accept`, ссылки-кнопки в письмах и чатах, меняющие состояние
сразу по переходу.

**Переопределение метода.** Middleware/параметр вроде `_method=POST`,
`X-HTTP-Method-Override` — превращают навигационный GET в «POST».

**Cookie-флаги.**
```python
# плохо
response.set_cookie("session", sid)
# хорошо
response.set_cookie("__Host-session", sid, httponly=True, secure=True,
                    samesite="lax", path="/")
```
Starlette `SessionMiddleware(same_site=..., https_only=True)` — проверить
параметры явно.

**API, принимающие «простые» типы.** Эндпоинт, читающий JSON, но не проверяющий
`Content-Type`: форма с `text/plain` уходит без preflight.

**Вход и OAuth.** Форма логина без защиты (login CSRF — жертву логинят в
аккаунт атакующего); OAuth-callback без проверки `state`.

**Браузерные расширения.** Background/service worker делает `fetch` к нашему API
с `credentials: 'include'` по сообщению от content script — любая страница,
где работает content script, может инициировать действие.

**Клиентский CSRF.** JS берёт путь или параметры из `location.hash`/query и сам
шлёт изменяющий запрос — токены и SameSite тут не помогают, запрос идёт со
своего origin.

## Как искать
```bash
rg -n '@(app|router)\.(post|put|patch|delete)\(' -t py   # затем сверить зависимости
rg -n '@(app|router)\.get\(.*(delete|remove|logout|accept|approve|confirm|unsubscribe|toggle|send)' -t py
rg -n 'set_cookie\(|SessionMiddleware\(|samesite|same_site' -t py
rg -n '_method|X-HTTP-Method-Override|method_override' -t py -t js
rg -n 'csrf|same_origin|Origin|Referer|Sec-Fetch-Site' -t py
rg -n "credentials:\s*['\"]include|withCredentials" -t js -t ts
rg -n 'state' -g '*oauth*' -g '*auth*' -t py
```
Вопросы ревьюера:
- Есть ли единое место, где проверяются ВСЕ небезопасные методы, или проверка
  навешивается вручную и её можно забыть?
- Нет ли GET с побочным эффектом (включая «одноразовые» ссылки)?
- Что делает проверка, если заголовка/токена нет вовсе?
- Доверяем ли мы поддоменам того же сайта (там может быть чужой код, XSS)?
- Как устроен роут, защищённый не сессией, а секретом (вебхуки, кнопки
  мессенджера)? Секрет проверяется до любого действия?

## Обходы, о которых забывают
- **Проверка только при наличии.** Токен/Origin сверяется, если пришёл, а
  отсутствие пропускается — атакующий просто не отправляет поле. Браузер не
  отправит Referer, если страница попросит (`Referrer-Policy`), а Origin бывает
  `null`.
- **Проверка только для части методов** (POST проверяем, PUT/DELETE/GET — нет).
- **Токен не привязан к сессии:** сервер принимает любой «свой» токен из общего
  пула — токен из аккаунта атакующего подходит жертве.
- **Наивный double submit** (значение в cookie = значение в поле): если
  атакующий может записать cookie (через поддомен, HTTP-версию сайта,
  CRLF-инъекцию), он подбирает пару сам. Нужна подпись HMAC с привязкой к сессии.
- **Нестрогое сравнение Origin/Referer:** «содержит», «начинается с»,
  «заканчивается на» пропускают домены, в имени которых есть наш. Сравнивать
  разобранный origin целиком.
- **SameSite=Lax — не защита для GET:** cookie уходят при навигации верхнего
  уровня, поэтому GET с побочным эффектом остаётся уязвимым; то же — при
  переопределении метода.
- **SameSite считает «сайтом» регистрируемый домен, а не origin:** запрос с
  соседнего поддомена (или со схемы-соседа) считается same-site. XSS или
  захват поддомена снимает защиту целиком.
- **Клиентские перенаправления на нашем сайте** (JS, меняющий `location` по
  параметру) превращают внешний переход во «внутренний» запрос — Strict не
  поможет.
- **Браузер по умолчанию ставит Lax**, только если атрибута нет, и в ряде
  браузеров с послаблениями для свежих cookie — полагаться на это нельзя,
  флаг нужно ставить явно.
- **CORS не защищает от CSRF:** простые формы и запросы уходят без preflight;
  CORS лишь ограничивает чтение ответа.
- **CAPTCHA и «кнопка подтверждения»** — не CSRF-защита.

## Как исправить правильно
1. Ни одного изменения состояния на GET/HEAD/OPTIONS.
2. Одна общая зависимость/middleware на все POST/PUT/PATCH/DELETE: проверка
   `Sec-Fetch-Site` (принимать `same-origin`, при необходимости `none`), иначе —
   точная сверка `Origin` со списком из конфигурации; при отсутствии обоих
   заголовков — отказ (или Referer как запасной вариант, тоже точная сверка).
   `null` не в белом списке.
3. Для форм, где этого мало, — синхронизирующий токен (CSPRNG, привязан к
   сессии, в скрытом поле или заголовке, не в URL) или подписанный double submit.
   Сравнение — `hmac.compare_digest`.
4. Сессионная cookie: `HttpOnly; Secure; SameSite=Lax` (Strict — где UX
   позволяет), префикс `__Host-`, без `Domain`.
5. API: требовать `Content-Type: application/json` и/или собственный заголовок —
   кросс-доменный запрос с ними уйдёт только через preflight.
6. Логин и OAuth: токен/`state` до входа, новая сессия после входа.
7. Опасные действия (смена почты, удаление данных) — повторное подтверждение.
8. Не забыть XSS: любая XSS обходит любую CSRF-защиту.

## Ложные срабатывания
- Роуты, где аутентификация не через cookie, а через заголовок
  `Authorization: Bearer`, который JS ставит сам (браузер его не прикладывает
  автоматически).
- Вебхуки и межсервисные эндпоинты с проверкой подписи/секрета — CSRF к ним
  неприменим (но проверить, что секрет действительно сверяется).
- GET-роуты, которые только читают; logout по POST.
- Проверка Origin в общем middleware, которую не видно в объявлении роута.

## Источники
- PortSwigger Web Security Academy (только ссылки, текст не заимствован):
  - https://portswigger.net/web-security/csrf
  - https://portswigger.net/web-security/csrf/bypassing-token-validation
  - https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
  - https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses
  - https://portswigger.net/web-security/csrf/preventing
- OWASP Cheat Sheet Series, CC BY-SA 4.0 — рекомендации по токенам, подписанному
  double submit, Fetch Metadata, сверке Origin, cookie-префиксам и типовым
  ошибкам адаптированы из Cross-Site Request Forgery Prevention Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
