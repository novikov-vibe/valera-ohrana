# Prototype pollution

## Суть
В JavaScript почти все объекты наследуют свойства от общего прототипа
`Object.prototype`. Если код копирует ключи из недоверенных данных в объект
(слияние, «глубокое присваивание по пути», разбор query-строки), специальные
ключи `__proto__` или `constructor` → `prototype` позволяют дописать свойство
в общий прототип — и его «увидят» все объекты приложения. Само загрязнение
безвредно; вред появляется, когда где-то есть **гаджет** — код, который читает
необязательное свойство (без собственного значения) и передаёт его в опасное
место. На клиенте это обычно ведёт к DOM-XSS, на сервере (Node.js) — к обходу
проверок, отказу в обслуживании, а в худшем случае к выполнению команд.

## Где появляется в коде
**Слияние и присваивание по пути.**
```js
// плохо: рекурсивный merge без фильтра ключей
function merge(dst, src) {
  for (const k in src) {
    if (typeof src[k] === 'object') merge(dst[k] ??= {}, src[k]);
    else dst[k] = src[k];
  }
}
merge(settings, JSON.parse(userJson));

// плохо: set(obj, 'a.b.c', value) с путём от пользователя
setByPath(state, params.get('path'), params.get('value'));

// хорошо: только известные ключи, без наследования
const ALLOWED = new Set(['theme', 'lang']);
const out = Object.create(null);
for (const [k, v] of Object.entries(src)) if (ALLOWED.has(k)) out[k] = v;
```
**Источники:** query-строка и фрагмент (особенно парсеры, понимающие вложенность
`a[b][c]`), JSON из запроса или сообщения (`JSON.parse` сохраняет `__proto__`
как обычный ключ), `postMessage`, сообщения расширения, `localStorage`.

**Гаджеты.**
```js
// опасно: опция может прийти из загрязнённого прототипа
const opts = {};
if (opts.transport_url) loadScript(opts.transport_url);
el.innerHTML = config.template || defaultTemplate;
fetch(url, { method: 'POST' });  // необязательные поля опций читаются с прототипа
```
Гаджеты часто живут в сторонних библиотеках (виджеты, аналитика, санитайзеры,
шаблонизаторы) и во встроенных API браузера — опции `fetch`, дескрипторы
`Object.defineProperty`.

**Уязвимые библиотеки.** Старые версии `lodash` (`merge`, `defaultsDeep`,
`set`, `zipObjectDeep`), `jquery.extend(true, ...)`, `deep-extend`,
`qs`/`query-string` с вложенностью, самописные `deepMerge`.

**Python-аналог.** Прямого аналога нет, но похожая ошибка — массовое
присваивание: `for k, v in data.items(): setattr(obj, k, v)` или
`obj.__dict__.update(data)` — меняет любые атрибуты, включая служебные
(`is_admin`, `role`). Лечится так же: белый список полей (pydantic-модель).

**Браузерные расширения.** Content script сливает данные со страницы или из
сообщения в объект настроек; background хранит состояние в обычных объектах и
мерджит туда входящие сообщения.

## Как искать
```bash
rg -n '__proto__|constructor\s*\[|\[\s*["\x27]constructor["\x27]\s*\]|\.prototype\s*\[' -t js -t ts
rg -n 'function\s+(deep)?[mM]erge|deepMerge|deepExtend|defaultsDeep|\$\.extend\(\s*true|_\.merge\(|_\.set\(|setByPath|setPath|dset\(' -t js -t ts
rg -n 'for\s*\(\s*(const|let|var)\s+\w+\s+in\s' -t js -t ts
rg -n '\w+\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*=' -t js -t ts      # obj[a][b] = ... с ключами из данных
rg -n 'Object\.assign\(\s*\w+\s*,\s*JSON\.parse' -t js -t ts
rg -n 'setattr\(|__dict__\.update\(' -t py
rg -n '"(lodash|jquery|deep-extend|qs|merge|hoek|minimist)"' -g 'package.json'
```
Вопросы ревьюера:
- Есть ли место, где ключи (а не только значения) приходят из недоверенных
  данных и записываются в объект, включая вложенные уровни?
- Какие версии библиотек слияния/разбора query используются, есть ли известные
  уязвимости (`npm audit`)?
- Где код читает необязательные свойства из объектов настроек и передаёт их в
  приёмники (`innerHTML`, `src`, `eval`, `child_process`, шаблоны)?

## Обходы, о которых забывают
- **Фильтр только `__proto__`:** путь через `constructor` и его `prototype`
  ведёт к тому же общему прототипу.
- **Нерекурсивная очистка:** если опасную подстроку вырезать один раз, из
  оставшихся частей может собраться та же подстрока. Фильтровать ключи целиком
  (точное сравнение), а не вырезать фрагменты, и на каждом уровне вложенности.
- **Фильтр в одном парсере, но не в другом:** JSON-тело проверяется, а
  query-строка или сообщение — нет; или фильтр на сервере, а слияние на клиенте.
- **Кодировки и альтернативные записи** ключа (URL-кодирование, точечная и
  скобочная нотация) обходят наивные проверки строки до разбора.
- **«Гаджетов нет»** — сегодня. Обновление библиотеки или новый код может
  добавить гаджет; исправлять источник надо всё равно.
- **`Object.freeze(Object.prototype)` поверхностный** и может ломать библиотеки,
  которые сами меняют прототипы; `Object.seal` не мешает менять существующие
  значения.
- **Флаг Node.js `--disable-proto`** убирает лишь аксессор `__proto__`, путь
  через `constructor` остаётся.
- **Объекты-опции с `{}`** всё равно наследуют загрязнённые свойства, даже если
  весь остальной код безопасен.

## Как исправить правильно
1. Не сливать недоверенные данные в объекты «как есть»: схема с белым списком
   ключей (zod/ajv на JS, pydantic на Python).
2. Для словарей с ключами от пользователя — `Map`/`Set` или
   `Object.create(null)` (`{ __proto__: null }` в литерале).
3. Если нужен merge — пропускать ключи `__proto__`, `constructor`, `prototype`
   точным сравнением на каждом уровне и копировать только собственные свойства
   (`Object.hasOwn`, `Object.entries`).
4. При чтении опций — проверять, что свойство собственное
   (`Object.hasOwn(opts, 'x')`), задавать значения по умолчанию явно.
5. Обновлять библиотеки слияния и разбора query; отключать вложенный разбор,
   если он не нужен.
6. Как второй слой — `Object.freeze(Object.prototype)` при старте (после
   проверки совместимости), на сервере — `--disable-proto=delete`.
7. В Python — pydantic-модели вместо `setattr` в цикле; запретить лишние поля
   (`extra="forbid"`).

## Ложные срабатывания
- `for...in` или `Object.assign` по объекту, ключи которого заданы в коде.
- `JSON.parse` без последующего слияния в долгоживущий объект — сам по себе
  `__proto__` в разобранном JSON остаётся собственным свойством и ничего не
  загрязняет.
- `obj[key] = value`, где `key` проверен по белому списку или берётся из enum.
- Использование `lodash` свежих версий с исправленными CVE (но проверить, нет ли
  самописного пути).

## Источники
- PortSwigger Web Security Academy (только ссылки, текст не заимствован):
  - https://portswigger.net/web-security/prototype-pollution
  - https://portswigger.net/web-security/prototype-pollution/javascript-prototypes-and-inheritance
  - https://portswigger.net/web-security/prototype-pollution/client-side
  - https://portswigger.net/web-security/prototype-pollution/server-side
  - https://portswigger.net/web-security/prototype-pollution/preventing
- OWASP Cheat Sheet Series, CC BY-SA 4.0 — рекомендации (Map/Set,
  `Object.create(null)`, `Object.freeze`, ограничения `Object.seal`,
  `--disable-proto=delete`) адаптированы из Prototype Pollution Prevention
  Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html
