# CORS (Cross-Origin Resource Sharing)

## Суть
CORS — способ сервера разрешить браузеру отдавать ответ скриптам с других
origin. Сам по себе он ничего не защищает: он только ослабляет политику одного
источника. Ошибка в настройке позволяет любому сайту, открытому у пользователя,
читать ответы нашего API с его сессией (данные, токены, расшифровки). И наоборот:
CORS не защищает от CSRF — запрос всё равно уходит, ограничивается только чтение.

## Где появляется в коде
**FastAPI / Starlette `CORSMiddleware`.**
```python
# плохо: любой origin + cookie
app.add_middleware(CORSMiddleware, allow_origin_regex=".*",
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
# плохо: регулярка без якорей и с неэкранированной точкой
allow_origin_regex=r"https://.*example.com"
# хорошо: явный список из конфигурации
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                   allow_credentials=True, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"])
```
Замечание: Starlette при `allow_origins=["*"]` и `allow_credentials=True`
подставляет в ответ **конкретный** Origin запроса — то есть фактически отражает
любой origin вместе с cookie. Это опасная комбинация.

**Ручные заголовки.**
```python
# плохо: отражение
resp.headers["Access-Control-Allow-Origin"] = request.headers.get("origin")
resp.headers["Access-Control-Allow-Credentials"] = "true"
# хорошо
origin = request.headers.get("origin")
if origin in ALLOWED_ORIGINS:
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Vary"] = "Origin"
```

**Белый список с `null`.** `allow_origins=["null", ...]` — «для локальных
файлов» или «для расширения».

**Внутренние сервисы.** Внутренний API без авторизации с
`Access-Control-Allow-Origin: *` — любой внешний сайт читает его через браузер
сотрудника.

**Браузерные расширения.** Разрешение на origin вида `chrome-extension://*` или
отражение любого `chrome-extension://…` — другие расширения тоже получают доступ;
нужен точный ID. Для расширений MV3 часто лучше вообще не CORS, а
`host_permissions` и запрос из service worker.

## Как искать
```bash
rg -n 'CORSMiddleware|allow_origins|allow_origin_regex|allow_credentials' -t py
rg -n 'Access-Control-Allow-(Origin|Credentials|Headers|Methods)' 
rg -n 'headers\.get\(["\x27]origin|request\.headers\[["\x27]origin' -i -t py
rg -n '["\x27]null["\x27]' -t py | rg -i 'origin'
rg -n 'endswith\(|startswith\(|in origin|re\.(match|search)\(' -t py | rg -i origin
rg -n 'chrome-extension://' 
```
Вопросы ревьюера:
- Нужен ли CORS вообще? Если фронт на том же origin — middleware не нужен.
- Какие origin разрешены и откуда берётся список (конфиг, а не код/запрос)?
- Отдаются ли с `Allow-Credentials` ответы с персональными данными?
- Есть ли `Vary: Origin`, если ACAO зависит от запроса (иначе кэш/CDN отдаст
  ответ с чужим разрешением)?
- Все ли origin в списке — только HTTPS и под нашим полным контролем?

## Обходы, о которых забывают
- **Отражение Origin** с credentials — то же, что «разрешено всем», только
  хуже: шаблон `*` браузер с cookie не принял бы, а отражённое значение примет.
- **Ошибки разбора белого списка:** проверка суффикса пропустит домен, который
  оканчивается на наше имя без точки-разделителя; проверка префикса — домен,
  где наше имя лишь начало; регулярка без `^…$` или с неэкранированной точкой
  совпадёт с посторонними строками.
- **`null` в белом списке:** значение `null` получает не только локальный файл,
  но и любая страница через песочницу iframe или после некоторых перенаправлений —
  атакующему его легко получить.
- **Доверие всем поддоменам:** XSS или захваченный (висящий DNS) поддомен
  становится плацдармом для чтения API с cookie.
- **Доверие HTTP-версии своего же домена:** сетевой атакующий подменяет
  незащищённую страницу и делает из неё запросы к HTTPS-API.
- **Внутренние сети без cookie:** даже без credentials `*` на интранет-сервисе
  превращает браузер сотрудника в прокси во внутреннюю сеть.
- **Preflight — не авторизация:** простые GET/POST уходят без OPTIONS, а
  инструменты вне браузера вообще игнорируют CORS. Права проверяются в роуте.
- **Кэширование:** без `Vary: Origin` прокси может закешировать ответ с одним ACAO
  и отдать его другим.

## Как исправить правильно
1. По умолчанию CORS не включать. Включать только для конкретных роутов,
   которым он реально нужен.
2. Явный список origin из конфигурации, точное сравнение строк
   (схема + хост + порт). Никаких отражений, суффиксов и общих регулярок.
3. `allow_credentials=True` — только с явным списком, никогда со `*` или `.*`.
4. `null` не разрешать никогда.
5. Только HTTPS-origin; для расширения — точный `chrome-extension://<id>`.
6. `Vary: Origin` на ответах, где ACAO вычисляется.
7. Ограничить методы и заголовки; `max_age` разумный.
8. Авторизация и CSRF-защита — независимо от CORS, на сервере.

## Ложные срабатывания
- `allow_origins=["*"]` **без** `allow_credentials` на действительно публичных
  данных (статус-страница, публичный справочник) — допустимо.
- Список из одного-двух точных HTTPS-origin из конфигурации.
- Регулярка с якорями и экранированием для фиксированного набора поддоменов,
  которые все под контролем команды (но проверить, что так и есть).
- Отсутствие CORS-настроек при одном origin фронта и API — это норма.

## Источники
- PortSwigger Web Security Academy (только ссылки, текст не заимствован):
  - https://portswigger.net/web-security/cors
  - https://portswigger.net/web-security/cors/same-origin-policy
  - https://portswigger.net/web-security/cors/access-control-allow-origin
- OWASP Cheat Sheet Series, CC BY-SA 4.0 — рекомендации по CORS (точный список
  доменов, `*` только для несекретного, preflight не заменяет контроль доступа,
  отказ от доверия одному лишь Origin) адаптированы из раздела
  «Cross Origin Resource Sharing» HTML5 Security Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
