# Валера Охрана

Скил для Claude Code: защитное ревью безопасности веб-приложения по темам
PortSwigger Web Security Academy и OWASP — инъекции, XSS, CSRF, IDOR,
OAuth/JWT, SSRF, загрузка файлов, гонки, кэш, атаки на LLM через промпт.

Инструкция для модели — в [`SKILL.md`](SKILL.md), справочники по темам —
в [`references/`](references/).

## Установка

```bash
git clone https://github.com/novikov-vibe/valera-ohrana ~/.claude/skills/valera-ohrana
```

После этого скил подхватится сам, когда просят проверить код на уязвимости,
или по имени: «позови Валеру».

## Источники и лицензии

См. [`NOTICE.md`](NOTICE.md). Идеи PortSwigger пересказаны своими словами
со ссылками; фрагменты OWASP Cheat Sheet Series адаптированы по CC BY-SA 4.0.
