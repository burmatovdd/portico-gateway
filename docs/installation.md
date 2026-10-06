# Установка

Все команды выполняются оператором из корня репозитория. В примерах используются условные адреса. Перед установкой заменить их на параметры своего окружения.

## 1. Подготовить зависимости

Обязательны Kubernetes, Helm, PostgreSQL для core, OIDC-провайдер и доступный узлам реестр образов. Создать отдельную БД и пользователя с правом создавать таблицы Portico. Для models дополнительно нужны LiteLLM и ограниченный служебный ключ.

Для внешнего доступа подготовить DNS и HTTPS. Если включён `gateway.enabled`, требуются Gateway API и существующий Gateway с HTTPS listener. CiliumNetworkPolicy требует установленного Cilium; в других кластерах отключить оба флага `networkPolicy.cilium*` и задать обычные NetworkPolicy.

Чарт не устанавливает БД, IdP, LiteLLM, чат, Strix или контроллер песочниц. Portico не требует PVC.

## 2. Собрать образ

```sh
docker build --platform linux/amd64 -f containers/Dockerfile -t registry.example.org/portico-gateway:pilot .
docker push registry.example.org/portico-gateway:pilot
```

Выбрать платформу узлов кластера. Один образ содержит `portico` и `portico-models`. Для закрытого контура доступны build arguments `GO_IMAGE` и `RUNTIME_IMAGE`; этап сборки также требует Go modules. После сборки сервис не загружает исполняемые зависимости из Интернета.

## 3. Заполнить Secret

```sh
cp deploy/secrets.example.yaml deploy/secrets.local.yaml
openssl rand -base64 32
openssl rand -hex 32
```

Первая команда генерации создаёт ключ шифрования, вторая — отдельный секрет серверного MCP-клиента.

| Поле `stringData` | Содержимое |
| --- | --- |
| `database-password` | Пароль PostgreSQL |
| `encryption-key` | Base64 от 32 случайных байт; общий для реплик и сохраняемый между обновлениями |
| `oidc-client-secret` | Секрет приложения Portico в IdP |
| `openwebui-client-secret` | Отдельный секрет MCP-клиента Open WebUI; такое же значение задаётся в чате |
| `litellm-api-key` | Служебный ключ LiteLLM; требуется при включённом models |

Имя Secret должно совпадать с `existingSecret`; namespace — с namespace релиза. Заполненный файл не публикуется. Ключ шифрования хранится вместе с защищённой резервной копией БД.

## 4. Заполнить values

`deploy/chart/values.yaml` содержит универсальные значения и не предназначен для установки без заполнения адресов и разрешений. Рабочий файл `deploy/values.yaml` исключён из Git. Для каждого окружения заполнить его на основе [примера](../deploy/values.example.yaml); см. [подготовку публикации](publication.md).

| Раздел | Что указывается |
| --- | --- |
| `image` | Собранный образ, tag и digest; непустой digest имеет приоритет |
| `imagePullSecrets` | Secret доступа к registry |
| `database` | host, port, databaseName, user, sslMode и CA БД |
| `existingSecret`, `oauthClientSecrets` | Ссылка на Secret и переменные секретов MCP-клиентов |
| `config.public_url` | Внешний HTTPS origin без пути |
| `config.oidc` | Issuer, Client ID, audience и claim разрешений |
| `config.oauth.clients` | Client ID, метод аутентификации и точные callback URI |
| `config.services` | Реестр API, операций и разрешённых групп |
| `models.config` | Политика моделей и фиксированный upstream LiteLLM |
| `certificates` | Доверенные CA исходящего HTTPS |
| `gateway` | Hostname и ссылка на существующий Gateway |
| `networkPolicy`, `models.networkPolicy` | Разрешённые источники и исходящие соединения |
| `nodeSelector`, `resources`, `models.resources` | Размещение и ресурсы |

Для core разрешить DNS, IdP, PostgreSQL и зарегистрированные API. Для models — DNS, IdP и LiteLLM. Вход разрешить Gateway и необходимым клиентам. Пустые сетевые правила не означают свободный доступ.

В `certificates` допустимы несколько PEM CA. Для PostgreSQL используется отдельное `database.certificates`. Режим `verify-full` проверяет CA и имя сервера; `require` без CA требует шифрования, но не проверки подлинности сервера. Сертификат внешнего HTTPS listener настраивается отдельно. Закрытые ключи не помещаются в ConfigMap.

## 5. Настроить IdP и установить

Выполнить [инструкцию IdP](idp.md). Для примера ниже скопировать универсальный values в локальный файл и заполнить его:

```sh
test ! -e deploy/values.yaml && cp deploy/values.example.yaml deploy/values.yaml
helm lint deploy/chart -f deploy/values.yaml
helm template portico-gateway deploy/chart -n portico -f deploy/values.yaml > /tmp/portico-rendered.yaml
```

Просмотреть результат. Для новой установки создать namespace с ограничениями Pod Security из `deploy/ns.yaml`. Этот пример использует профиль `restricted`; дополнительные компоненты с иными требованиями следует размещать отдельно. Для существующего namespace сначала проверить совместимость уже размещённых в нём компонентов. Затем:

```sh
kubectl apply -f deploy/ns.yaml
kubectl apply -f deploy/secrets.local.yaml
helm upgrade --install portico-gateway deploy/chart -n portico -f deploy/values.yaml --wait --timeout 5m
kubectl -n portico get pods
```

Таблицы core создаются при запуске. Models создаётся только при `models.enabled: true`. Рабочие значения всегда передаются отдельным файлом через `-f`.

После установки подключить [клиенты](clients.md) и выполнить [проверки](verification.md). Положительный статус readiness не подтверждает пользовательский OAuth-сценарий.
