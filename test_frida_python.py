# test_frida_python.py

import frida

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

def main():
    package_name = 'sleep'  # Используйте процесс sleep для теста

    device = frida.get_usb_device()

    try:
        pid = device.spawn([package_name, '1000'])  # 'sleep 1000'
        device.resume(pid)
        session = device.attach(pid)
        print(f'Подключено к процессу {package_name} (PID: {pid})')

        script = session.create_script("""
            // network_monitor.js

'use strict';

const tcpSocketFunctions = [
    {
        module: 'libc.so',
        exports: ['socket', 'connect', 'send', 'recv', 'close']
    }
];

const udpSocketFunctions = [
    {
        module: 'libc.so',
        exports: ['socket', 'sendto', 'recvfrom', 'close']
    }
];

// Константы для семейства адресов
const AF_INET = 2;
const AF_INET6 = 10;

// Функция для преобразования sockaddr_in и sockaddr_in6 в читаемый формат
function sockaddrToString(addrPtr) {
    if (addrPtr.isNull()) {
        console.log('sockaddrToString: addrPtr is NULL');
        return 'NULL';
    }

    try {
        const family = addrPtr.readU16();
        let ipStr = '';
        let port = 0;

        if (family === AF_INET) {
            port = addrPtr.add(2).readU16();
            const ip = addrPtr.add(4).readU32();
            ipStr = [
                (ip & 0xFF),
                (ip >> 8) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 24) & 0xFF
            ].join('.');
            return `${ipStr}:${port}`;
        } else if (family === AF_INET6) {
            // Обработка IPv6 адресов
            let ipBytes = [];
            for (let i = 0; i < 16; i++) {
                ipBytes.push(addrPtr.add(8 + i).readU8());
            }
            let segments = [];
            for (let i = 0; i < 16; i += 2) {
                segments.push(((ipBytes[i] << 8) | ipBytes[i + 1]).toString(16));
            }
            ipStr = segments.join(':');
            port = addrPtr.add(2).readU16();
            return `${ipStr}:${port}`;
        } else {
            return `Unknown family: ${family}`;
        }
    } catch (e) {
        console.error(`sockaddrToString: Exception occurred: ${e}`);
        return 'Error parsing sockaddr';
    }
}

// Функция для хукинга функций
function hookFunctions(moduleInfo, funcNames, isUDP = false) {
    funcNames.forEach(funcName => {
        const address = Module.findExportByName(moduleInfo.module, funcName);
        if (address === null) {
            console.warn(`hookFunctions: Функция ${funcName} не найдена в модуле ${moduleInfo.module}`);
            return;
        }

        console.log(`hookFunctions: Hooking ${funcName} at ${address}`);

        Interceptor.attach(address, {
            onEnter: function(args) {
                this.funcName = funcName;

                // Логирование количества аргументов и всех аргументов функции
                const argsLength = args.length;
                console.log(`onEnter: ${funcName} called with ${argsLength} arguments`);

                let argsStr = [];
                for (let i = 0; i < args.length; i++) {
                    try {
                        argsStr.push(`arg${i} = ${args[i].toString()}`);
                    } catch (e) {
                        argsStr.push(`arg${i} = [invalid pointer]`);
                    }
                }
                console.log(`onEnter: ${funcName} arguments: ${argsStr.join(', ')}`);

                if (funcName === 'socket') {
                    try {
                        this.domain = args[0].toInt32();
                        this.type = args[1].toInt32();
                        this.protocol = args[2].toInt32();
                        console.log(`[${funcName} onEnter] domain=${this.domain}, type=${this.type}, protocol=${this.protocol}`);
                    } catch (e) {
                        console.error(`[${funcName} onEnter] Error reading arguments: ${e}`);
                        this.domain = 'undefined';
                        this.type = 'undefined';
                        this.protocol = 'undefined';
                    }
                } else if (funcName === 'connect') {
                    try {
                        this.sockfd = args[0].toInt32();
                        this.addrPtr = args[1];
                        console.log(`[${funcName} onEnter] sockfd=${this.sockfd}, addrPtr=${this.addrPtr}`);
                        this.address = sockaddrToString(this.addrPtr);
                    } catch (e) {
                        console.error(`[${funcName} onEnter] Error reading arguments: ${e}`);
                        this.sockfd = 'undefined';
                        this.address = 'undefined';
                    }
                } else if (funcName === 'send' || funcName === 'recv') {
                    try {
                        this.sockfd = args[0].toInt32();
                        this.length = args[2].toInt32();
                        console.log(`[${funcName} onEnter] sockfd=${this.sockfd}, length=${this.length}`);
                    } catch (e) {
                        console.error(`[${funcName} onEnter] Error reading arguments: ${e}`);
                        this.sockfd = 'undefined';
                        this.length = 'undefined';
                    }
                } else if (funcName === 'sendto' || funcName === 'recvfrom') {
                    try {
                        this.sockfd = args[0].toInt32();
                        this.length = args[2].toInt32();
                        if (isUDP) {
                            if (args.length > 4) {
                                this.addrPtr = args[4];
                                console.log(`[${funcName} onEnter] sockfd=${this.sockfd}, length=${this.length}, addrPtr=${this.addrPtr}`);
                                if (!this.addrPtr.isNull()) {
                                    this.address = sockaddrToString(this.addrPtr);
                                } else {
                                    this.address = 'NULL';
                                    console.log(`[${funcName} onEnter] addrPtr is NULL`);
                                }
                            } else {
                                console.warn(`[${funcName} onEnter] Недостаточно аргументов для получения addrPtr`);
                                this.address = 'N/A';
                            }
                        }
                    } catch (e) {
                        console.error(`[${funcName} onEnter] Error reading arguments: ${e}`);
                        this.sockfd = 'undefined';
                        this.length = 'undefined';
                        this.address = 'undefined';
                    }
                } else if (funcName === 'close') {
                    try {
                        this.sockfd = args[0].toInt32();
                        console.log(`[${funcName} onEnter] sockfd=${this.sockfd}`);
                    } catch (e) {
                        console.error(`[${funcName} onEnter] Error reading arguments: ${e}`);
                        this.sockfd = 'undefined';
                    }
                }
            },
            onLeave: function(retval) {
                let log = {};

                try {
                    switch (this.funcName) {
                        case 'socket':
                            log = {
                                type: 'socket',
                                domain: this.domain,
                                typeSocket: this.type,
                                protocol: this.protocol,
                                return: retval.toInt32()
                            };
                            break;
                        case 'connect':
                            log = {
                                type: 'connect',
                                sockfd: this.sockfd,
                                address: this.address,
                                return: retval.toInt32()
                            };
                            break;
                        case 'send':
                        case 'recv':
                            log = {
                                type: this.funcName,
                                sockfd: this.sockfd,
                                length: this.length,
                                return: retval.toInt32()
                            };
                            break;
                        case 'sendto':
                        case 'recvfrom':
                            log = {
                                type: this.funcName,
                                sockfd: this.sockfd,
                                address: this.address,
                                length: this.length,
                                return: retval.toInt32()
                            };
                            break;
                        case 'close':
                            log = {
                                type: 'close',
                                sockfd: this.sockfd,
                                return: retval.toInt32()
                            };
                            break;
                        default:
                            break;
                    }

                    if (log.type) {
                        send(log);
                    }
                } catch (e) {
                    console.error(`onLeave: Exception in ${this.funcName}: ${e}`);
                }
            }
        });
    });

// Хуки для TCP функций
tcpSocketFunctions.forEach(moduleInfo => {
    hookFunctions(moduleInfo, moduleInfo.exports, false);
});

// Хуки для UDP функций
udpSocketFunctions.forEach(moduleInfo => {
    hookFunctions(moduleInfo, moduleInfo.exports, true);
});

// Обработчик сообщений для логирования
rpc.exports = {
    onMessage: function(message, data) {
        if (message.type === 'send') {
            // Форматирование вывода для удобства чтения
            let output = '';

            switch (message.payload.type) {
                case 'socket':
                    output = `[SOCKET] sockfd=${message.payload.return}, domain=${message.payload.domain}, type=${message.payload.typeSocket}, protocol=${message.payload.protocol}`;
                    break;
                case 'connect':
                    output = `[CONNECT] sockfd=${message.payload.sockfd}, address=${message.payload.address}, return=${message.payload.return}`;
                    break;
                case 'send':
                case 'recv':
                    output = `[${message.payload.type.toUpperCase()}] sockfd=${message.payload.sockfd}, length=${message.payload.length}, return=${message.payload.return}`;
                    break;
                case 'sendto':
                case 'recvfrom':
                    output = `[${message.payload.type.toUpperCase()}] sockfd=${message.payload.sockfd}, address=${message.payload.address}, length=${message.payload.length}, return=${message.payload.return}`;
                    break;
                case 'close':
                    output = `[CLOSE] sockfd=${message.payload.sockfd}, return=${message.payload.return}`;
                    break;
                default:
                    output = JSON.stringify(message.payload);
                    break;
            }

            console.log(output);

            // Запись в файл с временной меткой
            const logEntry = `${new Date().toISOString()} ${output}\n`;
            fs.appendFileSync('network_log.txt', logEntry);
        } else if (message.type === 'error') {
            console.error(`Frida Error: ${message.stack}`);
        }
    }
};

        """)
        script.on('message', on_message)
        script.load()
        print('Script loaded. Monitoring network connections...')
        import time
        while True:
            time.sleep(1)
    except Exception as e:
        print(f'Ошибка: {e}')

if __name__ == '__main__':
    main()
