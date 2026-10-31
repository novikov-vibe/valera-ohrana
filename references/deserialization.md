# Insecure deserialization

## Суть
Приложение восстанавливает объекты из данных, на которые влияет пользователь, с помощью
«нативного» механизма сериализации (pickle, YAML с тегами объектов, Java/PHP/.NET
serialization). Такой механизм выбирает класс и вызывает его методы ещё во время
разбора, поэтому атакующий получает выполнение кода, подмену прав (поле `is_admin` в
объекте сессии) или DoS — до того, как сработает любая проверка в коде.

## Где появляется в коде

**Python**:
```python
# плохо
obj = pickle.loads(base64.b64decode(request.cookies["state"]))
cfg = yaml.load(body, Loader=yaml.Loader)        # или UnsafeLoader / FullLoader в старых версиях
yaml.unsafe_load(text)
jsonpickle.decode(payload)
shelve.open(user_path); dill.loads(...); joblib.load(uploaded_file)
torch.load(uploaded_file)                        # pickle внутри; weights_only=False
numpy.load(f, allow_pickle=True); pandas.read_pickle(...)
# хорошо
data = json.loads(body)                          # затем Pydantic-модель
cfg = yaml.safe_load(text)
torch.load(path, weights_only=True)
```
Где ещё прячется:
- кэш/очередь, куда кладут pickle (Redis, Celery с `pickle`-сериализатором, RQ,
  `multiprocessing` через сеть) — опасно, если хранилище доступно не только нам;
- сессии на подписанных куках с pickle внутри: защищены ровно подписью и секретом;
  утёк `SECRET_KEY` — получили RCE;
- модели ML и артефакты, загружаемые пользователями или из внешних хабов;
- `yaml.load` в загрузке конфигов, присланных через API/админку.

**Node/JS**: `node-serialize.unserialize`, `serialize-javascript` + `eval`,
`funcster`; YAML `js-yaml.load` в версиях < 4 со схемой с функциями;
прототипное загрязнение при «глубоком слиянии» распарсенного JSON — родственная
проблема.
**Java**: `ObjectInputStream.readObject`, XStream, Jackson с default typing,
SnakeYAML `new Yaml()`. **PHP**: `unserialize($_COOKIE[...])`, `phar://`-обёртки в
файловых функциях. **.NET**: `BinaryFormatter`, `TypeNameHandling` в Json.NET.
**Ruby**: `Marshal.load`, `YAML.load` (Psych до 4).

## Как искать
```bash
rg -n "pickle\.(loads?|Unpickler)|cPickle|dill\.|cloudpickle|shelve\.open|jsonpickle" --type py
rg -n "yaml\.(load|unsafe_load|full_load)\(|Loader\s*=\s*yaml\.(Loader|UnsafeLoader|FullLoader)" --type py
rg -n "torch\.load\(|joblib\.load\(|read_pickle\(|allow_pickle\s*=\s*True|marshal\.loads" --type py
rg -n "task_serializer|accept_content|serializer\s*=\s*['\"]pickle" --type py
rg -n "unserialize\(|readObject\(|BinaryFormatter|TypeNameHandling|Marshal\.load|node-serialize"
```
Также смотреть трафик и хранилища: base64-строки в куках/полях формы, начинающиеся
с характерных префиксов pickle (`gASV`), Java (`rO0AB`) или PHP-подобные `O:4:"...":`.

Вопросы ревьюера:
- Откуда берутся сериализованные байты? Может ли пользователь их подменить
  (кука, скрытое поле, загружаемый файл, общий Redis, бакет)?
- Есть ли подпись/MAC, проверяемый **до** десериализации, и где хранится ключ?
- Нужна ли вообще нативная сериализация, или хватит JSON + схема?

## Обходы, о которых забывают
- **«Бинарный формат не прочтут»** — форматы pickle/Java/PHP хорошо задокументированы
  и инструментально генерируются; непрозрачность ≠ защита.
- **Проверка после разбора** бесполезна: опасный код выполняется внутри самого
  `loads()`, до проверки типа или `isinstance`.
- **Подмена только данных** без RCE: поменять поле роли, id пользователя, тип значения
  (строка ↔ число ↔ булево) и воспользоваться нестрогими сравнениями в логике.
- **Цепочки «гаджетов»**: даже если наши классы безобидны, библиотеки в окружении
  содержат методы, которые вызываются автоматически при восстановлении объекта и
  составляются в цепочку до опасного действия. Удалить «все гаджеты» нереально.
- **«Ограниченный Unpickler»** с переопределённым `find_class` — хрупок: любой
  пропущенный класс или модуль в белом списке становится лазейкой.
- **Косвенная десериализация**: файловая функция в PHP над путём с `phar://`
  десериализует метаданные архива, хотя `unserialize` в коде нет; аналогично ML-модели,
  `.npy` с объектами, «кэш» в shared-хранилище.
- **Подписанные данные с утёкшим или слабым ключом**: подпись — единственный барьер.

## Как исправить правильно
1. Для данных от пользователя и через границы доверия — только «чистые» форматы
   (JSON, MessagePack без расширений, protobuf) + строгая схема (Pydantic).
2. YAML — только `yaml.safe_load`; никаких пользовательских конструкторов объектов.
3. Если нативная сериализация неизбежна (внутренний кэш) — хранилище недоступно извне,
   данные подписаны HMAC и подпись проверяется до разбора, ключ ротируется.
4. Celery/очереди — сериализатор `json`, `accept_content=["json"]`.
5. ML-артефакты — `weights_only=True`, форматы safetensors/ONNX, загрузка только из
   доверенных источников с проверкой хэша.
6. Защита в глубину: изоляция процесса, разбирающего внешние объекты, мониторинг
   ошибок десериализации, обновление библиотек (меньше известных гаджетов).

## Ложные срабатывания
- `pickle` для файлов/кэша, которые пишет и читает только этот же процесс в закрытом
  каталоге (риск при компрометации другого компонента — отметить, но не критично).
- `yaml.load(..., Loader=yaml.SafeLoader)` или `CSafeLoader` — эквивалент safe_load.
- `json.loads`, `orjson.loads`, Pydantic — не восстанавливают произвольные классы.
- `itsdangerous`/подписанные куки с JSON-сериализатором (по умолчанию в Starlette
  `SessionMiddleware` — JSON + base64 + подпись).

## Источники
- PortSwigger Web Security Academy — Insecure deserialization:
  https://portswigger.net/web-security/deserialization
  (подстраницы: exploiting, exploiting/gadget-chains)
- OWASP Deserialization Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

Материал PortSwigger пересказан своими словами, тексты не копировались. Python-раздел
(pickle, PyYAML `safe_load` против `Loader`/`UnsafeLoader`, `jsonpickle.decode`),
признаки в трафике (префикс `gASV`, `rO0AB`) и общие меры (чистые форматы данных,
подпись до разбора) адаптированы из OWASP Deserialization Cheat Sheet, лицензия
CC BY-SA 4.0.
