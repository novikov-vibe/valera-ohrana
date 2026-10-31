# Path traversal (обход каталога)

## Суть
Приложение строит путь к файлу из недоверенной строки, и последовательности вроде
«на уровень вверх» или абсолютный путь выводят его за пределы разрешённого каталога.
Итог — чтение чужих записей, исходников, `.env`, ключей, а при записи — перезапись
конфигов и кода, что часто ведёт к выполнению кода. Родственный случай — доступ к
файлу другого пользователя внутри разрешённого каталога (это уже IDOR).

## Где появляется в коде

**Python / FastAPI / pathlib**:
```python
# плохо
return FileResponse(f"/srv/audio/{name}")
open(os.path.join(AUDIO_DIR, request.query_params["f"]), "rb")
Path(BASE) / user_path            # абсолютный user_path ЗАМЕНЯЕТ BASE целиком
os.path.join(BASE, "/etc/passwd")  # то же: join отбрасывает всё до абсолютного пути
# хорошо: файл ищется по id из БД, путь строит сервер
row = await conn.fetchrow("SELECT audio_path FROM calls WHERE id=$1", call_id)
# + проверка доступа к созвону, затем:
base = Path(AUDIO_DIR).resolve()
target = (base / row["audio_path"]).resolve()
if not target.is_relative_to(base):      # Python 3.9+
    raise HTTPException(404)
```
Другие места:
- `StaticFiles(directory=...)` безопасен, а самописные «отдай файл по имени» — нет;
- `UploadFile.filename` при сохранении (`dest / file.filename`) — запись куда угодно;
- распаковка архивов: `zipfile.extractall`, `tarfile.extractall` без фильтра — «Zip Slip»
  (имена членов архива с `../` или абсолютные; в tar — ещё и симлинки/хардлинки).
  В Python 3.12+ — `tar.extractall(filter="data")`;
- `send_file`, `shutil.copy/move`, `os.remove` с путём из ввода;
- Jinja2 `get_template(user_name)`, `importlib.import_module(user_name)`;
- ключи объектного хранилища (S3), собранные из ввода, — свой вид обхода префикса.

**Node/JS**: `path.join(base, req.params.f)` без проверки, `res.sendFile` без опции
`root`, `fs.readFile` с вводом, `adm-zip`/`unzipper` без проверки имён.
Хорошо — `res.sendFile(name, { root: BASE })` + проверка `path.relative`.
**Прочее**: Java `new File(base, input)`, PHP `include $_GET[...]` (ещё и LFI → RCE).

## Как искать
```bash
rg -n "(open|FileResponse|send_file|read_bytes|read_text|unlink|remove|rename)\(" --type py
rg -n "os\.path\.join\([^)]*(request|params|query|filename|name)" --type py
rg -n "Path\([^)]*\)\s*/\s*\w*(name|path|file)" --type py
rg -n "\.filename\b" --type py
rg -n "extractall\(|extract\(" --type py
rg -n "sendFile\(|readFile(Sync)?\(|path\.join\([^)]*req\." -g '*.{js,ts}'
```
Вопросы ревьюера:
- Почему имя файла вообще приходит от клиента? Можно ли передавать id записи?
- Где именно проверка: до декодирования или после? До `resolve()` или после?
- Учитываются ли симлинки внутри базового каталога?
- Проверяется ли ещё и **право** на конкретный файл (чей это созвон)?

## Обходы, о которых забывают
- **Удаление `../` одной заменой**: вложенная конструкция после вырезания внутренней
  части снова складывается в `../`. Нужна проверка результата, а не чистка ввода.
- **Абсолютный путь**: можно обойтись вообще без `..`, если `join`/`/` позволяет
  абсолютному аргументу заменить базу.
- **Кодирование**: URL-кодирование, двойное кодирование, «overlong» UTF-8,
  полноширинные символы и обратный слэш на Windows — фильтр видит одно, файловая
  система другое. Особенно опасна проверка, выполненная **до** финального декодирования
  (прокси декодирует ещё раз, фреймворк — ещё раз).
- **Требование префикса**: проверка `startswith("/srv/audio")` проходит для
  `/srv/audio/../../etc` и для соседнего каталога `/srv/audio_backup`. Сравнивать
  нужно канонические пути по компонентам (`is_relative_to`, `commonpath`).
- **Требование расширения**: в старых окружениях нулевой байт обрезал строку на уровне
  системного вызова; в современном Python это ошибка, но в других языках/обёртках
  бывает. Проверка «оканчивается на .mp3» не ограничивает каталог.
- **Симлинки и TOCTOU**: `resolve()` проверил одно, а к моменту `open()` в каталоге
  появилась ссылка. Опасно там, где пользователи могут создавать файлы в базовом
  каталоге (распаковка архивов с симлинками).
- **Windows-особенности**: `\`, диск `C:`, UNC-пути `\\host\share`, зарезервированные
  имена, хвостовые точки/пробелы.

## Как исправить правильно
1. Не принимать путь от пользователя: хранить файлы под сгенерированными именами
   (UUID), а клиенту давать id записи; путь берётся из БД.
2. Если имя всё же нужно — белый список (`^[A-Za-z0-9_-]{1,64}\.(mp3|wav)$`) и
   `Path(name).name == name` (нет разделителей).
3. Канонизировать и проверять: `(base / name).resolve()` → `is_relative_to(base.resolve())`;
   проверка — после всех декодирований и прямо перед использованием.
4. Распаковка: проверять каждый член архива тем же способом, запрещать
   симлинки/хардлинки/абсолютные имена, `tarfile` — `filter="data"`, лимит размера
   и числа файлов.
5. Защита в глубину: отдельный пользователь ОС без доступа к коду и секретам,
   каталог данных вне веб-корня, read-only монтирование там, где запись не нужна,
   плюс проверка доступа к самому объекту (404 для чужого).

## Ложные срабатывания
- `open()` с путём из конфигурации/констант без внешнего ввода.
- `StaticFiles` FastAPI/Starlette — внутри уже есть проверка выхода из каталога
  (но не включайте `follow_symlink=True` без нужды).
- Путь собран из UUID/int, прошедшего валидацию типа (`call_id: UUID`).
- `secure_filename` (Werkzeug) для имени при сохранении — убирает разделители,
  хотя лучше всё равно генерировать имя на сервере.

## Источники
- PortSwigger Web Security Academy — Path traversal:
  https://portswigger.net/web-security/file-path-traversal
- OWASP Input Validation Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- OWASP File Upload Cheat Sheet (раздел про имена файлов):
  https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Web Security Testing Guide — Directory Traversal File Include:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include

Материал PortSwigger пересказан своими словами, тексты не копировались. Принципы
«белый список вместо чёрного» и «канонизация перед проверкой» адаптированы из OWASP
Input Validation Cheat Sheet и File Upload Cheat Sheet, лицензия CC BY-SA 4.0.
