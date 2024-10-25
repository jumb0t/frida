// logger.js

const fs = require('fs');
const frida = require('frida');

// Замените на фактическое имя пакета вашего приложения
const packageName = 'Telegram'; // Например, 'com.example.app'

async function listLoadedLibraries(session) {
    try {
        const loadedModules = await session.enumerateModules();
        console.log('\nЗагруженные библиотеки:');
        loadedModules.forEach(lib => {
            console.log(`${lib.name} - ${lib.base.toString()}`);
        });

        // Фильтрация релевантных библиотек
        const relevantLibs = loadedModules.filter(lib => lib.name.includes('libc.so') || lib.name.includes('libc-'));
        console.log('\nРелевантные библиотеки для скрипта:');
        relevantLibs.forEach(lib => {
            console.log(`${lib.name} - ${lib.base.toString()}`);
        });
    } catch (err) {
        console.error(`Ошибка при перечислении модулей: ${err}`);
    }
}

async function getProcessInfo(device, pid) {
    try {
        const processes = await device.enumerateProcesses();
        const process = processes.find(proc => proc.pid === pid);
        if (process) {
            console.log('\nИнформация о процессе:');
            console.log(`Имя процесса: ${process.name}`);
            console.log(`PID: ${process.pid}`);
            console.log(`Родительский PID: ${process.ppid}`);
            console.log(`Путь к исполняемому файлу: ${process.path}`);
        } else {
            console.log('Не удалось получить информацию о процессе.');
        }
    } catch (err) {
        console.error(`Ошибка при получении информации о процессе: ${err}`);
    }
}

async function main() {
    try {
        const device = await frida.getUsbDevice();
        console.log('Подключено к устройству');

        // Перечисление процессов
        const processes = await device.enumerateProcesses();
        let targetProcess = processes.find(proc => proc.name === packageName);

        let session;
        if (targetProcess) {
            console.log(`Процесс ${packageName} найден (PID: ${targetProcess.pid}). Подключение...`);
            session = await device.attach(targetProcess.pid);
        } else {
            console.log(`Процесс ${packageName} не запущен. Запуск приложения...`);
            const pid = await device.spawn([packageName]);
            session = await device.attach(pid);
            await device.resume(pid);
            targetProcess = await device.enumerateProcesses().then(procs => procs.find(proc => proc.pid === pid));
            console.log(`Приложение ${packageName} запущено (PID: ${pid}). Подключение...`);
        }

        // Перечисление загруженных библиотек
        await listLoadedLibraries(session);

        // Получение информации о процессе
        await getProcessInfo(device, targetProcess.pid);

        // Вывод доступных методов объекта session для отладки
        console.log('Доступные методы session:', Object.getOwnPropertyNames(Object.getPrototypeOf(session)));

        // Создание и загрузка скрипта
        const scriptContent = fs.readFileSync('network_monitor.js', 'utf8');
        const script = await session.createScript(scriptContent);

        script.message.connect(message => {
            if (message.type === 'send') {
                // Обработка сообщений от network_monitor.js
                // Здесь уже происходит логирование в network_monitor.js, дополнительных действий не требуется
            } else if (message.type === 'error') {
                console.error(`Frida Error: ${message.stack}`);
            }
        });

        await script.load();
        console.log('\nСкрипт загружен. Начало перехвата сетевых соединений...\n');

    } catch (err) {
        console.error(`Ошибка: ${err}`);
    }
}

main();
