// test_enumerate_modules.js

const frida = require('frida');

async function main() {
    const packageName = 'Telegram'; // Убедитесь, что это точное имя процесса

    try {
        const device = await frida.getUsbDevice();
        console.log('Подключено к устройству');

        const processes = await device.enumerateProcesses();
        let targetProcess = processes.find(proc => proc.name === packageName);

        if (!targetProcess) {
            console.log(`Процесс ${packageName} не найден. Запуск...`);
            const pid = await device.spawn([packageName]);
            await device.resume(pid);
            targetProcess = await device.enumerateProcesses().then(procs => procs.find(proc => proc.pid === pid));
            console.log(`Процесс ${packageName} запущен (PID: ${pid})`);
        } else {
            console.log(`Процесс ${packageName} найден (PID: ${targetProcess.pid})`);
        }

        const session = await device.attach(targetProcess.pid);
        console.log('Session attached');

        // Вывод доступных методов объекта session для отладки
        console.log('Доступные методы session:', Object.getOwnPropertyNames(Object.getPrototypeOf(session)));

        // Проверка наличия метода enumerateModules
        if (typeof session.enumerateModules === 'function') {
            const modules = await session.enumerateModules();
            console.log('Загруженные модули:');
            modules.forEach(module => {
                console.log(`${module.name} - ${module.base.toString()}`);
            });
        } else {
            console.log('Метод enumerateModules отсутствует в объекте session');
        }

        await session.detach();
        console.log('Session detached');
    } catch (err) {
        console.error('Ошибка:', err);
    }
}

main();
