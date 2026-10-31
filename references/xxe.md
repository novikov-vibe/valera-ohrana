# XXE (XML external entity injection)

## Суть
XML-парсер по умолчанию или по настройке обрабатывает DTD, внешние сущности и
XInclude, и тогда документ от пользователя заставляет сервер прочитать локальный
файл, сходить по URL (SSRF во внутреннюю сеть и метаданные облака) или исчерпать
память «взрывом» вложенных сущностей. Уязвимость в настройках парсера, а не в логике
приложения, поэтому её легко пропустить там, где XML «не виден» — в загрузках файлов.

## Где появляется в коде

**Python**:
```python
# плохо: lxml с настройками, разрешающими DTD/сущности/сеть
parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
etree.fromstring(body, parser)
etree.parse(uploaded_file)        # проверить версию lxml и дефолты парсера
xml.dom.pulldom / xml.sax с включённым feature_external_ges
# хорошо: defusedxml для любого недоверенного XML
import defusedxml.ElementTree as ET
root = ET.fromstring(body, forbid_dtd=True)
# или явный парсер lxml
parser = etree.XMLParser(resolve_entities=False, load_dtd=False,
                         no_network=True, huge_tree=False, dtd_validation=False)
```
Замечания по Python:
- стандартные `xml.etree`/`minidom`/`sax` на Expat не загружают внешние сущности по
  умолчанию, но уязвимы к «взрыву» сущностей на старых Expat; `xmlrpc` — к бомбам
  распаковки. Для недоверенного ввода всё равно — `defusedxml`;
- в lxml значение `resolve_entities` по умолчанию менялось между версиями —
  не полагаться на дефолт, задавать явно;
- XInclude: `tree.xinclude()` или XSLT (`etree.XSLT` с `document()`) поверх
  пользовательского XML — отдельный путь к файлам;
- непрямые парсеры: `python-docx`/`openpyxl` (DOCX/XLSX — это ZIP с XML), SVG через
  `cairosvg`/`svglib`, SAML-библиотеки, RSS/Atom (`feedparser`), SOAP (`zeep`),
  XMP-метаданные изображений, `xmltodict` (использует Expat; опция
  `disable_entities`).

**Node/JS**: `libxmljs` с `noent: true`, `xml2js` (безопасен по сущностям),
`fast-xml-parser` (сущности — опция), `xmldom` + XPath/XSLT.
**Java** — самая частая платформа XXE: `DocumentBuilderFactory`, `SAXParserFactory`,
`XMLInputFactory`, `TransformerFactory` без `disallow-doctype-decl`.
**.NET**: `XmlDocument` с `XmlResolver`, `XmlReaderSettings.DtdProcessing = Parse`.
**PHP**: `LIBXML_NOENT`, `simplexml_load_string(..., LIBXML_NOENT)`.

## Как искать
```bash
rg -n "XMLParser\(|etree\.(parse|fromstring|XML|iterparse)\(|xinclude\(|XSLT\(" --type py
rg -n "resolve_entities\s*=\s*True|load_dtd\s*=\s*True|no_network\s*=\s*False|huge_tree\s*=\s*True" --type py
rg -n "xml\.(dom|sax|etree)|minidom|pulldom|xmltodict|feature_external_ges" --type py
rg -n "defusedxml" --type py      # где НЕ используется, хотя XML внешний
rg -n "noent\s*:\s*true|DocumentBuilderFactory|DtdProcessing\.Parse|LIBXML_NOENT"
```
Вопросы ревьюера:
- Где сервер разбирает XML из внешнего источника — тела запросов, загрузки (SVG,
  DOCX, XLSX, ODT, GPX, KML), вебхуки, SAML, фиды, ответы сторонних API?
- Какой парсер и с какими флагами? Указаны ли они явно?
- Принимает ли JSON-эндпоинт XML при смене `Content-Type` (автоматические
  парсеры фреймворка)?
- Вставляется ли пользовательская строка внутрь XML, который потом разбирает сервер
  (тогда атака через XInclude без своего DOCTYPE)?

## Обходы, о которых забывают
- **«У нас нет XML»** — но есть загрузка SVG-аватарок, офисных документов,
  импорт из других систем, SAML-вход. Скрытая поверхность — главный источник XXE.
- **Смена типа содержимого**: эндпоинт ждёт форму или JSON, но фреймворк/прокси
  принимает и XML, если клиент так объявил тело.
- **XInclude** работает, когда атакующий контролирует лишь фрагмент значения и не
  может задать DOCTYPE — запрет только DOCTYPE в тексте запроса этого не закрывает.
- **Слепая XXE**: ответ не содержит значений сущностей, но данные утекают через
  внешний DTD с сервера атакующего (внеполосно, HTTP/DNS) или через текст ошибки
  парсера, в которую попадает содержимое файла.
- **Блокировка внешних DTD ≠ безопасность**: если разрешены DTD и параметрические
  сущности, можно переиспользовать DTD-файл, уже лежащий в системе, и переопределить
  его сущности для error-based утечки.
- **Фильтр по строке `<!ENTITY`** обходится другими кодировками документа (UTF-16,
  UTF-7 и т. п.) — фильтр видит одно, парсер другое.
- **DoS** без чтения файлов: экспоненциальное раскрытие сущностей и очень глубокая
  вложенность; отключённые внешние сущности от этого не спасают.

## Как исправить правильно
1. Для любого недоверенного XML — `defusedxml` (`forbid_dtd=True`, если DTD не нужны)
   или парсер с явно выключенными DTD, внешними сущностями, сетью и XInclude.
2. Не включать XInclude/XSLT над пользовательским XML; если нужно — с резолвером,
   запрещающим файлы и сеть.
3. Предпочитать JSON, где выбор формата за нами; убедиться, что фреймворк не
   подключает XML-парсер к JSON-эндпоинтам.
4. Для SVG/DOCX — обрабатывать в изолированном процессе, а SVG при возможности
   растеризовать или очищать, не отдавая исходник пользователям (см. `file-upload.md`).
5. Защита в глубину: лимиты размера и распаковки, исходящий файрвол для воркеров
   (против SSRF), обновлённые libxml2/Expat, отсутствие секретов в читаемых файлах.

## Ложные срабатывания
- `xml.etree.ElementTree.fromstring` на XML, который сервер сгенерировал сам или
  получил из доверенного внутреннего источника.
- `defusedxml.*` с настройками по умолчанию.
- lxml с явно заданными `resolve_entities=False, no_network=True, load_dtd=False`.
- `xml2js` в Node — не раскрывает внешние сущности (но проверить версию и опции).
- Генерация XML (`ElementTree.tostring`, шаблоны) — не разбор, XXE нет (но может быть
  XML-инъекция при склейке строк).

## Источники
- PortSwigger Web Security Academy — XXE:
  https://portswigger.net/web-security/xxe
  (подстраницы: blind, xxe-injection/xinclude-attacks, file-upload через SVG)
- OWASP XML External Entity Prevention Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- OWASP XML Security Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html

Материал PortSwigger пересказан своими словами, тексты не копировались. Рекомендации по
Python (defusedxml и `forbid_dtd=True`, сверка версии Expat, ограничение размера и
распаковки самостоятельно) и перечень флагов парсеров Java/.NET/PHP адаптированы из
шпаргалок OWASP по XXE и XML Security, лицензия CC BY-SA 4.0.
