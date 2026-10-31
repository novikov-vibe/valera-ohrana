# WebSockets

## Суть
WebSocket — долгоживущий двусторонний канал, который открывается обычным
HTTP-рукопожатием, а дальше живёт своей жизнью. Все классические ошибки ввода
(инъекции, XSS при пересылке другим пользователям, обход прав) переносятся и
сюда, но проверок обычно меньше: middleware для HTTP-роутов к сообщениям не
применяется. Отдельная беда — межсайтовый захват (CSWSH): рукопожатие с cookie
и без проверки Origin позволяет чужой странице открыть канал от имени жертвы,
слать команды и **читать** ответы.

## Где появляется в коде
**FastAPI / Starlette.**
```python
# плохо: нет проверки Origin, личность — только из cookie, прав на сообщения нет
@app.websocket("/ws/calls/{call_id}")
async def ws(websocket: WebSocket, call_id: int):
    await websocket.accept()
    while True:
        msg = await websocket.receive_json()
        await handle(msg)                 # любое действие, любой call_id

# хорошо
@app.websocket("/ws/calls/{call_id}")
async def ws(websocket: WebSocket, call_id: int):
    if websocket.headers.get("origin") not in settings.ws_allowed_origins:
        await websocket.close(code=1008); return
    user = await auth.user_from_ws(websocket)          # сессия при рукопожатии
    if user is None or not await can_view_call(user, call_id):
        await websocket.close(code=1008); return
    await websocket.accept()
    async for raw in websocket.iter_text():
        if len(raw) > 64_000: await websocket.close(code=1009); return
        msg = Message.model_validate_json(raw)          # схема, белый список типов
        await authorize(user, msg)                      # права на каждое действие
```
Важно: `Depends(auth.current_user)` и CSRF-зависимости, рассчитанные на HTTP,
в WebSocket-роуте могут не сработать или сработать иначе — проверять явно.

**Клиент.**
```js
// плохо: адрес из параметра страницы
const ws = new WebSocket(params.get('ws'));
ws.onmessage = e => log.innerHTML += e.data;
// хорошо
const ws = new WebSocket(`wss://${location.host}/ws/calls/${Number(callId)}`);
ws.onmessage = e => { const m = JSON.parse(e.data); line.textContent = m.text; };
```

**Доверие заголовкам рукопожатия.** `X-Forwarded-For`, `X-Real-IP`, кастомные
заголовки для лимитов, логов или «внутренних» прав.

**Токен в URL** (`wss://host/ws?token=...`) — оседает в логах прокси и истории.

**Браузерные расширения.** Background/offscreen-документ держит сокет к нашему
серверу и выполняет команды из сообщений content script без проверки; адрес
сокета собирается из настроек, которые может изменить страница.

## Как искать
```bash
rg -n '@(app|router)\.websocket|WebSocketEndpoint|websocket_route|WebSocket\b' -t py
rg -n 'websocket\.accept\(|receive_(text|json|bytes)|iter_(text|json|bytes)' -t py
rg -n 'headers\.get\(["\x27]origin' -i -t py
rg -n 'X-Forwarded-For|X-Real-IP|forwarded' -i -t py
rg -n 'new WebSocket\(|ws://' -t js -t ts
rg -n '\?token=|query_params\.get\(["\x27](token|key|auth)' -t py -t js
```
Вопросы ревьюера:
- Проверяется ли Origin при рукопожатии, точным списком?
- Как определяется пользователь: cookie (тогда нужен Origin/токен против
  CSWSH) или токен в первом сообщении?
- Проверяется ли доступ к ресурсу (созвон, комната) при подключении И права на
  каждое действие в сообщении? Не доверяет ли сервер `user_id`/`call_id` из
  сообщения?
- Что происходит при выходе пользователя или потере доступа — канал закрывается?
- Есть ли лимиты: размер сообщения, частота, число соединений, таймаут простоя?
- Пересылаются ли сообщения одного пользователя другим — как они показываются?

## Обходы, о которых забывают
- **SameSite не всегда спасает от CSWSH:** запрос с соседнего поддомена — тот
  же сайт, cookie уйдут; при `SameSite=None` защиты нет вовсе. Нужна проверка
  Origin на сервере.
- **`Sec-WebSocket-Key` — не защита:** это механизм против кэширующих прокси,
  а не секрет и не токен.
- **CORS к WebSocket не применяется:** браузер не блокирует кросс-доменное
  подключение и не ограничивает чтение ответов — всё решает сервер.
- **Проверка только при подключении:** после входа можно слать любые типы
  сообщений с любыми идентификаторами, если права не проверяются для каждого.
- **Сессия истекла, сокет жив:** долгоживущее соединение переживает logout и
  отзыв прав.
- **Нестрогая сверка Origin** (подстрока, суффикс) — те же ошибки, что в CORS.
- **Доверие клиентским заголовкам рукопожатия** — `X-Forwarded-For` подставляет
  кто угодно, если прокси не перезаписывает его.
- **Клиентская фильтрация сообщений:** проверки в JS-клиенте обходятся
  подключением своим клиентом.
- **Адрес сокета из пользовательских данных** (WebSocket-URL poisoning) —
  клиент подключается к чужому серверу и отправляет туда данные/токены.

## Как исправить правильно
1. Только `wss://`.
2. При рукопожатии: точная проверка `Origin` по списку из конфигурации, затем
   аутентификация (cookie сессии + Origin, или одноразовый короткоживущий
   токен в первом сообщении; не в URL).
3. Проверка доступа к ресурсу при подключении тем же правилом, что и для HTTP
   (единый предикат), ответ — закрытие с кодом 1008.
4. Каждое сообщение: схема (pydantic), белый список типов, авторизация действия,
   идентификаторы ресурса — из контекста соединения, а не из сообщения.
5. Лимиты: размер сообщения, частота на пользователя, число соединений на
   пользователя/IP, таймаут простоя, ping/pong; backpressure.
6. Закрывать соединения при logout/истечении сессии, периодически
   перепроверять сессию.
7. На клиенте — адрес сокета из констант, входящие данные в безопасные
   приёмники (`textContent`), разбор через `JSON.parse`.
8. Логировать подключения и отказы (пользователь, origin), но не содержимое
   сообщений и не токены.

## Ложные срабатывания
- Публичный сокет без аутентификации и без персональных данных (например,
  общий статус сервиса) — CSWSH ничего не даёт.
- Аутентификация токеном в первом сообщении, который JS берёт из своего
  состояния, — CSWSH к ней неприменим (но проверить, что до проверки токена
  сервер ничего не отдаёт).
- Проверка Origin, вынесенная в общий ASGI-middleware для `scope["type"] ==
  "websocket"`.

## Источники
- PortSwigger Web Security Academy (только ссылки, текст не заимствован):
  - https://portswigger.net/web-security/websockets
  - https://portswigger.net/web-security/websockets/what-are-websockets
  - https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- OWASP Cheat Sheet Series, CC BY-SA 4.0 — рекомендации по рукопожатию,
  токенам, авторизации сообщений, лимитам, таймаутам и журналированию
  адаптированы из WebSocket Security Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
