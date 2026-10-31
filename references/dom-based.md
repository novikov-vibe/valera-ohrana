# DOM-based уязвимости (источники и приёмники)

## Суть
Клиентский JS берёт значение, которое может контролировать посторонний
(**источник**), и без проверки передаёт его в функцию или свойство, которое
делает что-то опасное (**приёмник**). Сервер в этом не участвует и часто вообще
не видит данных (фрагмент `#...` в запрос не уходит), поэтому серверные фильтры
и WAF тут бессильны. Кроме DOM-XSS (см. `xss.md`) это открытые редиректы на
клиенте, подмена URL запросов и WebSocket, манипуляция cookie, атрибутами,
хранилищем, обработчики `postMessage` и DOM clobbering.

## Где появляется в коде
**Источники:** `location` (`href`, `search`, `hash`, `pathname`), `document.URL`,
`document.referrer`, `document.baseURI`, `window.name`, `document.cookie`,
`localStorage`/`sessionStorage`/IndexedDB, данные `message`-событий, ответы
API с пользовательским содержимым, `URLSearchParams`, в расширениях —
сообщения `chrome.runtime.onMessage`, DOM чужой страницы, читаемый content script.

**Приёмники по типам:**
| Тип | Примеры |
|---|---|
| Открытый редирект | `location = x`, `location.href/assign/replace(x)`, `window.open(x)` |
| Выполнение кода | `eval`, `Function`, `setTimeout(str)`, `el.onclick = str` |
| Ссылки/ресурсы | `a.href`, `script.src`, `iframe.src`, `form.action`, `img.src` |
| Запросы | `fetch(x)`, `XMLHttpRequest.open(..., x)`, `setRequestHeader`, `new WebSocket(x)` |
| Хранилище/cookie | `document.cookie = x`, `localStorage.setItem(k, x)` |
| Сообщения | `postMessage(x, '*')` |
| Прочее | `JSON.parse` с последующим доверием, `new RegExp(x)` (ReDoS), `document.domain` |

**Открытый редирект на клиенте.**
```js
// плохо: возврат после входа
location.href = new URLSearchParams(location.search).get('next');
// хорошо: только относительный путь своего приложения
const next = params.get('next') || '/';
const u = new URL(next, location.origin);
location.href = (u.origin === location.origin) ? u.pathname + u.search : '/';
```
**Обработчик `postMessage`.**
```js
// плохо
window.addEventListener('message', e => { panel.innerHTML = e.data.html; });
// плохо: подстрока
if (e.origin.indexOf('example.com') > -1) ...
// хорошо
if (e.origin !== 'https://app.example.com') return;
if (typeof e.data?.type !== 'string') return;
panel.textContent = String(e.data.text ?? '');
```
Отправка: `target.postMessage(data, '*')` — данные получит любой, кто окажется
в окне. Указывать точный `targetOrigin`.

**Браузерные расширения.**
- Content script слушает `window.postMessage` страницы и пересылает в
  background — любая страница с content script может управлять расширением.
- `chrome.runtime.onMessageExternal` / `externally_connectable` без проверки
  `sender.origin`/`sender.id`.
- Background выполняет `fetch(msg.url)` или `chrome.tabs.update({url: msg.url})`
  по данным из сообщения.
- Content script читает текст чужой страницы (заголовок встречи, имена) и
  вставляет его в свой UI через `innerHTML`.

**DOM clobbering.** Код читает глобальную переменную с запасным значением
(`window.config || {}`, `document.someId`), а на странице можно оставить HTML
с `id`/`name` — элемент подменит ожидаемый объект.

## Как искать
```bash
rg -n 'location(\.href|\.search|\.hash|\.pathname)?|document\.(URL|referrer|baseURI|cookie)|window\.name|URLSearchParams' -t js -t ts
rg -n '(location(\.href)?\s*=|location\.(assign|replace)\(|window\.open\()' -t js -t ts
rg -n "addEventListener\(\s*['\"]message|onmessage\s*=" -t js -t ts
rg -n "postMessage\([^)]*['\"]\*['\"]" -t js -t ts
rg -n '\.origin\.(indexOf|includes|startsWith|endsWith)|origin\.match\(' -t js -t ts
rg -n 'onMessage(External)?\.addListener|externally_connectable|runtime\.connect' -t js -t ts -g 'manifest.json'
rg -n '\.(src|href|action)\s*=|new WebSocket\(|setRequestHeader\(|document\.cookie\s*=' -t js -t ts
rg -n 'window\.\w+\s*\|\||document\.\w+\s*\|\|' -t js -t ts
```
Вопросы ревьюера:
- Для каждого приёмника: откуда приходит значение, есть ли путь от
  пользовательского источника?
- В обработчике сообщений: проверяется ли origin точным сравнением, ДО
  использования данных? Проверяется ли структура данных?
- Есть ли в расширении путь «страница → content script → background → действие
  с правами расширения»?
- Куда может уйти пользователь по параметрам `next`, `return`, `redirect`?

## Обходы, о которых забывают
- **Сервер не видит фрагмент:** валидация параметров на бэкенде не спасает,
  если клиент читает `location.hash`.
- **Нестрогая проверка origin:** `indexOf`, `includes`, `startsWith`,
  `endsWith` и регулярки без якорей пропускают домены атакующего, содержащие
  наше имя; проверка `e.source === iframe.contentWindow` без origin тоже слаба,
  если в iframe можно загрузить чужую страницу.
- **Проверка origin есть, но не там:** условие в одной ветке, а данные
  используются и в другой; или проверка после побочного эффекта.
- **«Только относительные пути»** через проверку первого символа `/`: путь,
  начинающийся с двух слэшей или слэша и обратного слэша, браузер трактует как
  адрес другого хоста. Разбирать через `new URL` и сравнивать `origin`.
- **Схема в URL:** `javascript:` и `data:` в `location`, `href`, `window.open` —
  это уже выполнение кода, а не редирект.
- **Хранимые DOM-уязвимости:** значение, однажды записанное в
  `localStorage`/cookie/`window.name`, срабатывает позже на другой странице.
- **jQuery `$(строка)`** при определённых входных данных создаёт элементы, а
  не ищет их.
- **Clobbering обходит санитайзер**, если тот разрешает `id`/`name`: HTML без
  скриптов всё равно меняет поведение кода.

## Как исправить правильно
1. Главное правило — не давать недоверенным данным определять значение,
   уходящее в опасный приёмник. Где можно — карта «ключ → заранее известное
   значение» вместо прямой передачи (`next=calls` → `/calls`).
2. URL: разбирать `new URL(x, location.origin)`, проверять `protocol` из белого
   списка и `origin` точным сравнением.
3. `postMessage`: точный `targetOrigin` при отправке; при приёме — точное
   сравнение `event.origin` со списком, затем проверка схемы данных; данные
   только в безопасные приёмники (`textContent`).
4. Расширения: проверять `sender` (`sender.id === chrome.runtime.id`,
   `sender.tab`, `sender.url`/`origin`), белый список типов сообщений, URL для
   `fetch` — только из констант/конфигурации расширения; `externally_connectable`
   — минимальный список `matches`.
5. Против clobbering: не использовать глобалы с `||`-запасом, проверять тип
   прочитанного (`instanceof`, `typeof`), санитайзер, учитывающий clobbering
   (DOMPurify).
6. `new RegExp` из пользовательского ввода — экранировать или не делать.

## Ложные срабатывания
- `location.href = '/calls/' + Number(id)` — значение приводится к числу.
- Редирект на значение из константы/ответа нашего API, которое пользователь не
  контролирует.
- Обработчик `message`, который проверяет `event.origin === location.origin` или
  точный список и использует только `textContent`.
- Чтение `location.pathname` для подсветки активного пункта меню.

## Источники
- PortSwigger Web Security Academy (только ссылки, текст не заимствован):
  - https://portswigger.net/web-security/dom-based
  - https://portswigger.net/web-security/dom-based/open-redirection
  - https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
  - https://portswigger.net/web-security/dom-based/dom-clobbering
  - https://portswigger.net/web-security/cross-site-scripting/dom-based
- OWASP Cheat Sheet Series, CC BY-SA 4.0 — адаптировано:
  - правила для Web Messaging — раздел HTML5 Security Cheat Sheet,
    https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
  - валидация редиректов (белый список, разбор URL, отказ от префиксных
    проверок) — Unvalidated Redirects and Forwards Cheat Sheet,
    https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
  - список опасных приёмников — DOM based XSS Prevention Cheat Sheet,
    https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
