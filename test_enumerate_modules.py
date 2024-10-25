# test_enumerate_modules.py

import frida

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

def main():
    package_name = 'org.telegram.messenger'  # Замените на точное имя процесса

    device = frida.get_usb_device()

    try:
        pid = device.spawn([package_name])
        device.resume(pid)
        session = device.attach(pid)
        print(f'Подключено к процессу {package_name} (PID: {pid})')

        modules = session.enumerate_modules()
        print('Загруженные модули:')
        for module in modules:
            print(f"{module.name} - {module.base_address}")

        session.detach()
        print('Session detached')

    except frida.ProcessNotFoundError:
        print(f'Процесс {package_name} не найден.')
    except Exception as e:
        print(f'Ошибка: {e}')

if __name__ == '__main__':
    main()
