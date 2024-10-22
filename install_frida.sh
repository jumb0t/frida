#!/bin/bash

# Скрипт для установки Frida Server на эмулятор Genymotion с использованием установленной версии Frida

# Функция для вывода сообщений
echo_info() {
    echo -e "\e[32m[INFO]\e[0m $1"
}

echo_error() {
    echo -e "\e[31m[ERROR]\e[0m $1" >&2
}

# Проверка наличия необходимых инструментов
command -v adb >/dev/null 2>&1 || { echo_error "adb не установлен. Установите adb и повторите попытку."; exit 1; }
command -v wget >/dev/null 2>&1 || { echo_error "wget не установлен. Установите wget и повторите попытку."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo_error "jq не установлен. Установите jq и повторите попытку."; exit 1; }
command -v frida >/dev/null 2>&1 || { echo_error "Frida не установлена. Установите Frida и повторите попытку."; exit 1; }

# Проверка подключённых устройств
DEVICE_COUNT=$(adb devices | grep -w "device" | wc -l)
if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo_error "Нет подключённых устройств. Убедитесь, что эмулятор Genymotion запущен и adb распознаёт его."
    exit 1
fi

# Получение идентификатора подключённого устройства
DEVICE_ID=$(adb devices | grep -w "device" | awk 'NR==1{print $1}')

echo_info "Подключено устройство: $DEVICE_ID"

# Определение архитектуры устройства
ARCH=$(adb -s "$DEVICE_ID" shell getprop ro.product.cpu.abi | tr -d '\r')

echo_info "Архитектура устройства: $ARCH"

# Функция для определения правильного названия архитектуры для Frida
get_frida_arch() {
    case "$1" in
        armv7l|armeabi-v7a)
            echo "arm"
            ;;
        aarch64|arm64-v8a)
            echo "arm64"
            ;;
        x86)
            echo "x86"
            ;;
        x86_64)
            echo "x86_64"
            ;;
        *)
            echo_error "Неизвестная архитектура: $1"
            exit 1
            ;;
    esac
}

FRIDA_ARCH=$(get_frida_arch "$ARCH")
echo_info "Frida будет установлена для архитектуры: $FRIDA_ARCH"

# Получение версии Frida с помощью frida --version
FRIDA_VERSION_RAW=$(frida --version)

if [ $? -ne 0 ] || [ -z "$FRIDA_VERSION_RAW" ]; then
    echo_error "Не удалось определить версию Frida. Убедитесь, что Frida установлена корректно."
    exit 1
fi

# Очистка версии от возможных префиксов, например, "12.8.20"
FRIDA_VERSION=$(echo "$FRIDA_VERSION_RAW" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

if [ -z "$FRIDA_VERSION" ]; then
    echo_error "Неверный формат версии Frida: $FRIDA_VERSION_RAW"
    exit 1
fi

echo_info "Используется версия Frida: $FRIDA_VERSION"

# Формирование URL для загрузки Frida Server
FRIDA_SERVER_NAME="frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}.xz"
FRIDA_DOWNLOAD_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER_NAME}"

echo_info "Скачивание Frida Server с URL: $FRIDA_DOWNLOAD_URL"

# Скачивание Frida Server
wget -q --show-progress "$FRIDA_DOWNLOAD_URL" -O "/tmp/${FRIDA_SERVER_NAME}"

if [ $? -ne 0 ]; then
    echo_error "Не удалось скачать Frida Server. Проверьте доступность URL или корректность версии."
    exit 1
fi

echo_info "Frida Server успешно скачан: /tmp/${FRIDA_SERVER_NAME}"

# Распаковка Frida Server
echo_info "Распаковка Frida Server..."

unxz "/tmp/${FRIDA_SERVER_NAME}"

FRIDA_SERVER_PATH="/tmp/frida-server-${FRIDA_VERSION}-android-${FRIDA_ARCH}"

if [ ! -f "$FRIDA_SERVER_PATH" ]; then
    echo_error "Не удалось распаковать Frida Server."
    exit 1
fi

echo_info "Frida Server распакован: $FRIDA_SERVER_PATH"

# Передача Frida Server на устройство
REMOTE_PATH="/data/local/tmp/frida-server"

echo_info "Передача Frida Server на устройство..."

adb -s "$DEVICE_ID" push "$FRIDA_SERVER_PATH" "$REMOTE_PATH"

if [ $? -ne 0 ]; then
    echo_error "Не удалось передать Frida Server на устройство."
    exit 1
fi

# Установка прав на выполнение
echo_info "Установка прав на выполнение Frida Server..."

adb -s "$DEVICE_ID" shell chmod 755 "$REMOTE_PATH"

# Запуск Frida Server
echo_info "Запуск Frida Server на устройстве..."

# Проверка наличия root-доступа
adb -s "$DEVICE_ID" shell "which su" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    adb -s "$DEVICE_ID" shell "su -c 'nohup $REMOTE_PATH >/dev/null 2>&1 &'"
else
    adb -s "$DEVICE_ID" shell "nohup $REMOTE_PATH >/dev/null 2>&1 &"
fi

# Проверка, запущен ли Frida Server
sleep 2  # Ждём немного для запуска процесса

FRIDA_RUNNING=$(adb -s "$DEVICE_ID" shell ps | grep frida-server | wc -l)

if [ "$FRIDA_RUNNING" -ge 1 ]; then
    echo_info "Frida Server успешно запущен на устройстве."
    echo_info "Frida готов к использованию!"
else
    echo_error "Не удалось запустить Frida Server на устройстве."
    exit 1
fi

# Очистка временных файлов
echo_info "Очистка временных файлов..."

rm -f "/tmp/${FRIDA_SERVER_NAME}"
rm -f "$FRIDA_SERVER_PATH"

echo_info "Установка завершена успешно."
