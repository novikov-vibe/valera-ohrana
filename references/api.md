# API: mass assignment, скрытые параметры, лишние методы

## Суть
API часто умеет больше, чем показывает интерфейс: недокументированные эндпоинты,
методы, типы содержимого и поля. Если сервер автоматически переносит все поля
запроса в объект (mass assignment), принимает лишние методы или вставляет
пользовательский ввод в запросы к внутренним сервисам без кодирования, клиент
меняет то, что менять не должен: роль, владельца, статус, чужие параметры.

## Где появляется в коде
- `UPDATE ... SET` собирается из `body.dict()` / `model_dump()` / `**request.json()`.
- Одна pydantic-модель используется и для чтения, и для записи (вход содержит `role`,
  `owner_id`, `is_admin`, `verified`, `created_by`).
- `extra="allow"` или ручной `await request.json()` без схемы.
- `@app.api_route(..., methods=["GET","POST","PUT","DELETE"])` на одном обработчике;
  `GET` меняет данные.
- Документация `/docs`, `/redoc`, `/openapi.json` открыта в проде; старые версии
  `/v1/` без тех же проверок.
- Ввод пользователя подставляется в URL/JSON запроса к внутреннему API через
  f-строку (server-side parameter pollution).

```python
# плохо: всё из тела — в SET
@app.patch("/users/{uid}")
async def patch_user(uid: int, request: Request, user=Depends(current_user)):
    data = await request.json()
    cols = ", ".join(f"{k}=${i+2}" for i, k in enumerate(data))   # ещё и имена колонок от клиента
    await db.execute(f"UPDATE users SET {cols} WHERE id=$1", uid, *data.values())

# хорошо: отдельная входная модель с allowlist, запрет лишних полей
class UserSelfUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: constr(max_length=80) | None = None
    timezone: str | None = None

@app.patch("/me")
async def patch_me(body: UserSelfUpdate, user=Depends(current_user)):
    data = body.model_dump(exclude_unset=True)
    ALLOWED = {"display_name": "display_name", "timezone": "timezone"}
    ...
```

```python
# плохо: ввод в запрос к внутреннему сервису
await http.get(f"{INTERNAL}/users?name={name}&public=true")
# хорошо: параметры передаются структурой, библиотека кодирует
await http.get(f"{INTERNAL}/users", params={"name": name, "public": "true"}, timeout=10)
# путь: проверять формат сегмента и кодировать quote(seg, safe="")
```

Node: `Object.assign(user, req.body)`, `User.update(req.body)`, `new Model(req.body)` —
опасно; правильно `_.pick(req.body, ['displayName','timezone'])` или схема `zod.strict()`.

## Как искать
```
rg -n 'model_dump\(|\.dict\(\)|\*\*(body|data|payload)|request\.json\(\)' app/
rg -n 'extra\s*=\s*.allow|Extra\.allow' app/
rg -n 'SET \{|f".*UPDATE|f".*INSERT' app/                 # динамический SQL из ключей
rg -n 'api_route\(|methods=\[' app/
rg -n 'docs_url|redoc_url|openapi_url' app/
rg -n 'f"https?://|f"\{.*(URL|HOST|BASE)' app/            # ввод в URL внутренних запросов
rg -n 'Object\.assign\(.*req\.body|\.update\(req\.body|new \w+\(req\.body' src/
```
Вопросы ревьюера:
- Какие поля у объекта в ответе GET? Какие из них клиенту можно менять? Совпадает ли
  входная схема ровно с этим списком?
- Есть ли поля, которые меняет только админ или только система (роль, статус,
  владелец, флаги проверки, счётчики)? Отклоняет ли их пользовательский роут?
- Какие методы принимает каждый путь? Что делает метод, о котором не подумали?
- Какие `Content-Type` принимаются? Не включается ли другой парсер (XML, form) с иными
  проверками?
- Пользовательский ввод попадает в запрос к другому сервису? Кодируется ли он и
  проверяется ли формат?
- Открыта ли документация API и старые версии эндпоинтов? Защищены ли они так же?

## Обходы, о которых забывают
- **Поля, которых нет в форме.** Интерфейс отправляет два поля, но сервер принимает
  все поля модели. Подсказка для атакующего — ответ GET: какие поля там есть, те
  можно попробовать прислать в PATCH.
- **Blocklist устаревает.** Новый столбец (`is_superuser`, `tenant_id`) автоматически
  становится записываемым, если защита — список запрещённых полей.
- **Вложенные объекты и конструкторы.** Allowlist на верхнем уровне, но вложенная
  модель (`profile.role`) или привязка через конструктор пропускает лишнее.
- **Другой метод — другой код.** `PUT` заменяет объект целиком и не проходит проверки
  `PATCH`; `DELETE` забыли защитить; `OPTIONS`/`HEAD` выдают данные.
- **Другой тип содержимого.** Переключение JSON → form/XML меняет парсер: другие
  проверки, многословные ошибки, иногда XXE.
- **Старые и тестовые версии.** `/api/v1/` или стенд без новых проверок доступа.
- **Загрязнение параметров на сервере.** Если ввод вставляется во внутренний запрос
  строкой, символы-разделители (`&`, `#`, `=`, `/`, `..`, кавычки в JSON) добавляют
  параметры, обрезают хвост с ограничениями или меняют путь. Дубли параметров разные
  фреймворки разрешают по-разному (первый, последний, оба).
- **Документация как карта.** Открытый OpenAPI показывает внутренние и админские
  эндпоинты; описание может быть устаревшим, но атакующий проверит всё.

## Как исправить правильно
- Отдельные входные модели (DTO) на каждое действие: «пользователь правит себя»,
  «админ правит пользователя», «создание». `extra="forbid"`. Выходные модели — свои.
- Allowlist полей вместо blocklist; имена колонок в SQL — только из словаря
  в коде, никогда из ключей запроса.
- Авторизация остаётся отдельно: allowlist ограничивает поля, но не решает, можно ли
  этому пользователю этот объект.
- Явный список методов на роут; изменяющие запросы — не через GET; 405 для остального.
- Принимать только ожидаемый `Content-Type` (415 для остальных); лимит размера тела.
- Внутренние запросы — через параметры библиотеки (`params=`, `json=`), сегменты
  пути — проверка формата и `quote(..., safe="")`.
- Документацию API в проде — закрыть или за вход; старые версии — удалить или
  защитить тем же кодом.
- Единообразные общие ошибки без деталей (см. `information-disclosure.md`).

## Ложные срабатывания
- `model_dump()` от модели, где все поля действительно разрешены пользователю.
- `request.json()` во вебхуке с проверкой подписи и разбором конкретных полей.
- Публичная документация публичного API — задуманное поведение.

## Источники
- PortSwigger Web Security Academy (только ссылки):
  https://portswigger.net/web-security/api-testing ,
  https://portswigger.net/web-security/api-testing/server-side-parameter-pollution
- OWASP Mass Assignment Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- OWASP REST Security Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

Рекомендации «DTO вместо доменных объектов», «allowlist вместо blocklist», «проверять
вложенные объекты и конструкторы», «авторизация отдельно от allowlist», «allowlist
методов (405), строгий `Content-Type` (415), лимит тела (413), закрытые
management-эндпоинты» адаптированы из шпаргалок OWASP (CC BY-SA 4.0). Материалы
PortSwigger пересказаны своими словами, без копирования.
