# Cross-site scripting (XSS)

## Суть
Данные, которые контролирует посторонний, попадают в страницу так, что браузер
воспринимает их как разметку или код, и этот код выполняется от имени жертвы на
нашем origin: читает данные страницы, шлёт запросы с её сессией, меняет интерфейс.
Три формы: отражённая (данные из текущего запроса сразу в ответ), хранимая (данные
сохранены в БД и показаны другим) и DOM-XSS (сервер ни при чём, опасную вставку
делает клиентский JS). Защита всегда зависит от **контекста вывода**: одно и то же
экранирование не годится для тела HTML, атрибута, URL, JS-строки и CSS.

## Где появляется в коде
**Серверные шаблоны (Jinja2).**
- `Environment(autoescape=False)` или `select_autoescape` без нужных расширений
  (например, шаблоны `.j2`/`.txt`, которые на деле отдаются как HTML).
- `{{ x|safe }}`, `Markup(user_text)`, `Markup(f"...{x}...")`, `{% autoescape false %}`.
- Переменная внутри `<script>`: `var name = "{{ name }}";` — автоэкранирование
  HTML здесь не то, что нужно.
- Переменная в атрибуте без кавычек: `<div class={{ cls }}>`.
- Переменная в `href`/`src`: `<a href="{{ url }}">` — HTML-экранирование не
  запрещает опасную схему.
- Переменная в `style="..."` или в `<style>`.

**HTML, собранный вручную.**
```python
# плохо
return HTMLResponse(f"<p>Привет, {name}</p>")
# хорошо
return templates.TemplateResponse(request, "hello.html", {"name": name})
# или хотя бы html.escape(name, quote=True) для текста/атрибута в кавычках
```
Сюда же — письма, сообщения в мессенджер с HTML/Markdown-разметкой, PDF/HTML-экспорт.

**Ванильный JS (DOM-XSS).**
```js
// плохо
el.innerHTML = `<b>${item.title}</b>`;
list.insertAdjacentHTML('beforeend', row);
// хорошо
const b = document.createElement('b'); b.textContent = item.title; el.append(b);
```
Опасные приёмники: `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`document.write(ln)`, `Range.createContextualFragment`, `DOMParser` + вставка,
`setAttribute('on…')`, `el.onclick = "строка"`, `eval`, `new Function`,
`setTimeout/setInterval` со строкой, `a.href = userUrl`, `iframe.src`, `srcdoc`,
jQuery `$(html)`, `.html()`, `.append(str)`, `.attr('href', …)`.

**JSON внутри HTML.** `<script>window.DATA = {{ data|tojson }}</script>` — `tojson`
в Jinja2 экранирует `<`, `>`, `&`, `'`, это правильно. А вот
`json.dumps(data)` + `|safe` — нет: строка с закрывающим тегом скрипта завершит блок.

**Ответы-«не HTML».** JSON/текст, отданные с `text/html` или без
`X-Content-Type-Options: nosniff`; загруженные файлы (SVG, HTML) с того же origin.

**Браузерные расширения.** Content script, который вставляет текст со страницы
(названия встреч, имена участников) через `innerHTML` в свой оверлей; popup,
рендерящий ответ сервера через `innerHTML`; страницы расширения с ослабленной CSP.

## Как искать
```bash
rg -n '\|\s*safe\b|Markup\(|autoescape\s*=\s*False|autoescape false' --type-add 'tpl:*.{html,j2,jinja}' -t py -t tpl
rg -n 'HTMLResponse\(\s*f["\x27]|HTMLResponse\(.*(\+|%|\.format)' -t py
rg -n '<script[^>]*>[^<]*\{\{' -g '*.html' -g '*.j2'
rg -n '(href|src|action|formaction|style|on\w+)\s*=\s*["\x27]?\{\{' -g '*.html'
rg -n 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment|srcdoc' -t js -t ts -g '*.html'
rg -n '\beval\(|new Function\(|setTimeout\(\s*["\x27`]|setInterval\(\s*["\x27`]' -t js -t ts
rg -n 'json\.dumps\(.*\).*\|\s*safe|dangerouslySetInnerHTML|v-html|bypassSecurityTrust' 
rg -n 'Content-Security-Policy|nosniff' -t py
```
Вопросы ревьюера:
- Для каждого вывода: в каком контексте окажутся данные (текст, атрибут, URL,
  JS-строка, CSS, комментарий)? Есть ли кодирование именно под него?
- Откуда пришла строка? «Из нашей БД» не значит «безопасная»: её туда мог
  записать пользователь, модель, внешняя система (календарь, чат, транскрипция).
- Вывод ИИ-модели (выжимки, заголовки) — тоже недоверенные данные.
- Есть ли где-то вставка «HTML от пользователя»? Если да — чем санитизируется?
- Какой `Content-Type` у ответов с пользовательскими данными, раздаются ли
  загруженные файлы с основного домена?

## Обходы, о которых забывают
- **Экранирование не под тот контекст.** HTML-экранирование не защищает внутри
  `<script>`: браузер сначала режет документ на теги, и последовательность,
  закрывающая скрипт, завершит блок раньше, чем JS-парсер увидит кавычки.
- **Атрибут без кавычек** ломается от пробела — экранировать угловые скобки
  бесполезно, можно добавить новый атрибут-обработчик.
- **URL-атрибуты.** `href`, `src`, `action`, `formaction` выполняют код при
  схеме `javascript:` (и `data:` в ряде мест) без всякого выхода из атрибута.
  Проверка «начинается с http» на сыром значении обходится пробелами, регистром,
  управляющими символами — сначала разобрать URL, потом сверить схему.
- **Обработчики событий.** Значение `onclick="..."` сначала HTML-декодируется,
  потом исполняется как JS: HTML-сущности превращаются обратно в кавычки.
- **Ручное экранирование кавычек** без экранирования обратного слэша —
  подставленный слэш «съедает» добавленный.
- **Шаблонные литералы JS** (обратные кавычки): кавычки не нужны вовсе, опасна
  конструкция `${`.
- **Клиентские шаблонизаторы** (AngularJS `ng-app`, Vue-шаблоны из серверного
  HTML): двойные фигурные скобки в пользовательском тексте вычисляются как
  выражение, хотя HTML-экранирование корректно.
- **`innerHTML` не запускает `<script>`** — это не защита: обработчики событий
  на других элементах срабатывают.
- **Чёрные списки** тегов/слов/символов всегда неполны: есть другие теги,
  регистр, кодировки, вызовы без скобок.
- **Двойная обработка:** санитизировали, а потом изменили строку (замена,
  Markdown-рендер, обрезка) — гарантии санитайзера больше нет.
- **CSP не страховка от всего:** `'unsafe-inline'`, `'unsafe-eval'`, разрешённые
  CDN и домены с JSONP/пользовательскими загрузками, предсказуемый или
  статичный nonce, отражение ввода в сам заголовок политики (через `;` можно
  дописать директивы). Даже строгая CSP оставляет утечки через разметку
  (незакрытые атрибуты, картинки, ссылки) — «висячая разметка».
- **Санитайзер устарел:** у DOMPurify и аналогов регулярно находят обходы
  через мутации разметки — версию нужно обновлять.

## Как исправить правильно
1. Автоэкранирование шаблонизатора включено для всех HTML-шаблонов; `|safe` и
   `Markup` — только на строках, собранных из констант или прошедших санитайзер.
2. Данные в JS — только через `|tojson` (в атрибут `data-*` или
   `<script type="application/json">` с последующим `JSON.parse`), не прямой
   вставкой в код.
3. Атрибуты — всегда в кавычках; имена атрибутов и тегов — константы.
4. URL от пользователя — разобрать (`urllib.parse`, `new URL`) и пропустить
   только `http`/`https` (или относительные пути по белому списку).
5. В JS — `textContent`, `createElement`, `setAttribute` с безопасным именем,
   `append`. HTML от пользователя — только через DOMPurify (или серверный
   `nh3`/bleach-аналог) с белым списком тегов.
6. Заголовки: `Content-Type` точный, `X-Content-Type-Options: nosniff`;
   загруженные файлы — с `Content-Disposition: attachment` или с отдельного домена.
7. CSP как второй слой: `script-src 'self'` или nonce/hash + `'strict-dynamic'`,
   `object-src 'none'`, `base-uri 'none'`, `frame-ancestors`; nonce — новый на
   каждый ответ из CSPRNG. По возможности Trusted Types
   (`require-trusted-types-for 'script'`).
8. Сессионная cookie — `HttpOnly` (снижает ущерб, но XSS не лечит).

## Ложные срабатывания
- `|safe`/`Markup` на строке, целиком собранной из констант или уже прошедшей
  `escape()`/санитайзер в этом же месте.
- `innerHTML = ''` (очистка) и `innerHTML` со статичной разметкой без переменных.
- `|tojson` внутри `<script>` — корректно (Jinja2 экранирует опасные символы).
- `HTMLResponse` с f-строкой, где подставлены только числа/enum/значения из
  конфигурации.
- `textContent`/`innerText` — безопасные приёмники (кроме элементов
  `<script>`/`<style>`).

## Источники
- PortSwigger Web Security Academy (только ссылки, текст не заимствован):
  - https://portswigger.net/web-security/cross-site-scripting
  - https://portswigger.net/web-security/cross-site-scripting/reflected
  - https://portswigger.net/web-security/cross-site-scripting/stored
  - https://portswigger.net/web-security/cross-site-scripting/dom-based
  - https://portswigger.net/web-security/cross-site-scripting/contexts
  - https://portswigger.net/web-security/cross-site-scripting/content-security-policy
  - https://portswigger.net/web-security/cross-site-scripting/dangling-markup
  - https://portswigger.net/web-security/cross-site-scripting/preventing
- OWASP Cheat Sheet Series, CC BY-SA 4.0 — списки безопасных приёмников,
  правила кодирования по контекстам и типовые ошибки адаптированы из:
  - Cross Site Scripting Prevention Cheat Sheet —
    https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - DOM based XSS Prevention Cheat Sheet —
    https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
