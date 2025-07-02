# Отчёт по практике: Анализ системных вызовов с eBPF

## ФИО:

Куликова Алёна Владимировна

## Группа:

КБ-9

## Дата:

02.07.2025

## 1. Цель работы

В работе была выполнена подготовка:

```
Установить Ubuntu 22.04 в виртуальной машине (рекомендуется выставить network device на bridge для возможности подключения по ssh и др.).
Установить bpftrace и bcc.
Проверить работу bpftrace через команду:
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("execve: %s\n", str(args->filename)); }'
Протестировать работу bpftrace, открыв другой терминал и введя разные команды (напр. ls или ping -q 1 8.8.8.8). Если в первом терминале появилась информация о вводимых командах, значит все установилось успешно.
```

проверка (bpftrace)

```
vboxuser@xubu:~$ sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("execve: %s\n", str(args->filename)); }'
Attaching 1 probe...
execve: /bin/bash
execve: /usr/bin/groups
execve: /usr/bin/lesspipe
execve: /usr/bin/basename
execve: /usr/bin/dirname
execve: /usr/bin/dircolors
execve: /usr/bin/ping
^C
```

проверка (пинг)

```
vboxuser@xubu:~$ ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=255 time=16.6 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=255 time=17.2 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=255 time=15.8 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=255 time=17.7 ms
64 bytes from 8.8.8.8: icmp_seq=5 ttl=255 time=48.5 ms
64 bytes from 8.8.8.8: icmp_seq=6 ttl=255 time=16.8 ms
^C
--- 8.8.8.8 ping statistics ---
6 packets transmitted, 6 received, 0% packet loss, time 5259ms
rtt min/avg/max/mdev = 15.783/22.095/48.532/11.836 ms
vboxuser@xubu:~$ 
```

![1](https://github.com/user-attachments/assets/98911c25-c09e-487b-909e-5eabf0fd326e)


а также тестовый раздел для понимания для дальнейшей работы:

```
Изучив примеры bpf_trace.py, collect_all.bt, разработайте свой скрипт (на выбор: bpftrace или Python+BCC), который:

отслеживает релевантные системные вызовы
выводит: человекочитаемый таймстамп, имя пробы (probe), PID, команду (comm), путь к исполняемому скрипту (filename, если применимо)
Выберите tracepoint'ы для отслеживания probe, которые кажутся вам важными
```

## 2. Выбранные проб-пойнты и обоснование

| Проб-пойнт       | Системный вызов | Обоснование выбора                                                                                                                                         |
|-----------------------|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| sys_enter_openat    | openat             | Позволяет отслеживать операции открытия файлов. Это важно для мониторинга доступа к файлам и выявления потенциальных несанкционированных операций        |
| sys_enter_execve    | execve             | Отслеживает выполнение новых процессов. Полезно для анализа запуска приложений и выявления подозрительных действий в системе                               |
| sys_enter_unlink    | unlink             | Позволяет отслеживать удаление файлов. Это критично для обеспечения безопасности и предотвращения несанкционированного удаления важных данных               |
| sys_enter_connect    | connect            | Позволяет отслеживать сетевые соединения. Это важно для анализа сетевой активности, выявления подозрительных подключений и мониторинга взаимодействия приложений с сетью |

## 3. Скрипт

Работа осуществляется на XUBUNTU.

Информация о системе:

```
Информация о системе:

Дата и время: Вт 24 июн 2025 21:35:36 +03
Имя хоста: xubu
Операционная система: GNU/Linux
Версия ядра: 6.8.0-60-generic
Архитектура: x86_64
Количество процессоров: 4
Использование диска:
awk: line 1: runaway regular expression / ...
Использование памяти:
               total        used        free      shared  buff/cache   available
Mem:           7,8Gi       711Mi       4,3Gi       2,0Mi       2,8Gi       6,8Gi
Swap:          2,0Gi          0B       2,0Gi
Список запущенных процессов:
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root        2274  0.3  1.3 348840 112452 tty7    Ssl+ 21:02   0:06 /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
vboxuser    2605  0.0  1.2 1211372 98228 ?       Sl   21:02   0:01 xfwm4 --replace
root        7525  0.1  1.0 445364 84328 ?        Ssl  21:26   0:00 /usr/libexec/fwupd/fwupd
root        4721  0.1  0.8 2046456 73036 ?       Ssl  21:12   0:01 dockerd --group docker --exec-root=/run/snap.docker --data-root=/var/snap/docker/common/var-lib-docker --pidfile=/run/snap.docker/docker.pid --config-file=/var/snap/docker/3265/config/daemon.json
vboxuser    2719  0.0  0.7 453796 63348 ?        Sl   21:02   0:00 /usr/bin/python3 /usr/lib/ubuntu-release-upgrader/check-new-release-gtk
vboxuser    3079  0.1  0.7 553676 57328 ?        Sl   21:02   0:02 mousepad /home/vboxuser/trace_sys/trace_syscalls.py
vboxuser    2686  0.0  0.6 372492 49932 ?        Sl   21:02   0:00 /usr/bin/python3 /usr/bin/blueman-applet
vboxuser    2886  0.0  0.6 476104 48892 ?        Sl   21:02   0:00 /usr/bin/xfce4-terminal
vboxuser    2634  0.1  0.6 468524 48832 ?        Sl   21:02   0:02 Thunar --daemon
```

Работа состоит из следующего:


1.Содержание requirements.txt:

находится в https://github.com/Kulikova-A18/ebpf_prac/blob/main/src/requirements.txt

```
bcc
numba
pytest
```

2.Содержание run_trace.sh:

код находится в https://github.com/Kulikova-A18/ebpf_prac/blob/main/src/run_trace.sh

```
#!/bin/bash

if [[ ! -f requirements.txt ]]; then
    echo "Файл requirements.txt не найден!"
    exit 1
fi

while IFS= read -r package; do
    echo "Установка пакета: $package"
    if ! dpkg -l | grep -q "$package"; then
        sudo apt install -y "$package"
    else
        echo "Пакет $package уже установлен."
    fi
done < requirements.txt

python3 trace_syscalls.py

```

3.Содержание trace_syscalls.py:

код находится в https://github.com/Kulikova-A18/ebpf_prac/blob/main/src/trace_syscalls.py

```
from bcc import BPF
import datetime
import socket
import struct
import logging

logging.basicConfig(filename='syscall_trace.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char event[16];
    char path[256];
    u32 ip;
    u16 port;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(&data.event, "OPEN", 4);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(&data.event, "EXEC", 4);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(&data.event, "UNLINK", 6);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    struct sockaddr addr = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.event, "CONNECT", 7);

    bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr);

    if (addr.sa_family == AF_INET) {
        struct sockaddr_in s = {};
        bpf_probe_read_user(&s, sizeof(s), args->uservaddr);

        data.ip = s.sin_addr.s_addr;
        data.port = ntohs(s.sin_port);
    }

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=program)
print("Tracing syscalls (openat, execve, unlink, connect)... Ctrl-C to exit.\n")

def ip_to_str(ip):
    try:
        return socket.inet_ntoa(struct.pack("I", ip))
    except Exception as e:
        logging.error(f"Error converting IP: {e}")
        return "0.0.0.0"

def print_event(cpu, data, size):
    try:
        event = b["events"].event(data)
        now = datetime.datetime.now().strftime("%H:%M:%S")
        comm = event.comm.decode('utf-8', 'replace')
        evt = event.event.decode('utf-8', 'replace')
        path = event.path.decode('utf-8', 'replace')

        if evt == "CONNECT" and event.ip != 0:
            ip = ip_to_str(event.ip)
            message = f"{now}-tracepoint:syscalls:sys_enter_connect PID: {event.pid:<6} COMM:<{comm}> PATH:<{ip}:{event.port}>"
            print(message)
            logging.info(message)
        else:
            message = f"{now}-tracepoint:syscalls:sys_enter_{evt.lower()} PID: {event.pid:<6} COMM:<{comm}> PATH: {path}"
            print(message)
            logging.info(message)

    except Exception as e:
        logging.error(f"Error processing event: {e}")

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
    except Exception as e:
        logging.error(f"Error in perf_buffer_poll: {e}")

```

по итогу работы создается syscall_trace.log

![image](https://github.com/user-attachments/assets/22e95d99-92a0-49c0-85d6-c8607e22178c)

## 4. Пример логов

можно посмотреть в https://github.com/Kulikova-A18/ebpf_prac/blob/main/src/syscall_trace.log

```
2025-07-02 20:20:07,117 - INFO - 20:20:07-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:07,117 - INFO - 20:20:07-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:07,117 - INFO - 20:20:07-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:07,118 - INFO - 20:20:07-tracepoint:syscalls:sys_enter_open PID: 2706   COMM:<Thunar> PATH: /usr/share/icons/elementary-xfce/mimes/64/text-x-generic.png
2025-07-02 20:20:08,343 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:08,343 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:08,343 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:08,343 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_exec PID: 7490   COMM:<bash> PATH: /usr/bin/ping
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 7490   COMM:<ping> PATH: /etc/ld.so.cache
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 7490   COMM:<ping> PATH: /lib/x86_64-linux-gnu/libcap.so.2
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 7490   COMM:<ping> PATH: /lib/x86_64-linux-gnu/libidn2.so.0
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 7490   COMM:<ping> PATH: /lib/x86_64-linux-gnu/libc.so.6
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 7490   COMM:<ping> PATH: /lib/x86_64-linux-gnu/libunistring.so.2
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 7490   COMM:<ping> PATH: 
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_open PID: 7490   COMM:<ping> PATH: /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
2025-07-02 20:20:08,344 - INFO - 20:20:08-tracepoint:syscalls:sys_enter_connect PID: 7490   COMM:<ping> PATH:<8.8.8.8:1025>
2025-07-02 20:20:10,045 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:10,045 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:10,045 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:10,459 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_open PID: 2036   COMM:<VBoxService> PATH: /var/run/utmp
2025-07-02 20:20:10,460 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /usr/local/share/dbus-1/system-services
2025-07-02 20:20:10,460 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /usr/share/dbus-1/system-services
2025-07-02 20:20:10,460 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /lib/dbus-1/system-services
2025-07-02 20:20:10,460 - INFO - 20:20:10-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /var/lib/snapd/dbus-1/system-services/
2025-07-02 20:20:11,088 - INFO - 20:20:11-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:11,088 - INFO - 20:20:11-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:11,089 - INFO - 20:20:11-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:12,107 - INFO - 20:20:12-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:12,108 - INFO - 20:20:12-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:12,108 - INFO - 20:20:12-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:12,867 - INFO - 20:20:12-tracepoint:syscalls:sys_enter_open PID: 2706   COMM:<Thunar> PATH: /home/vboxuser/ebpf_prac/src/.hidden
2025-07-02 20:20:13,131 - INFO - 20:20:13-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:13,131 - INFO - 20:20:13-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:13,131 - INFO - 20:20:13-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:14,155 - INFO - 20:20:14-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:14,155 - INFO - 20:20:14-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:14,155 - INFO - 20:20:14-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:15,177 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:15,177 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:15,177 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:15,463 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 2036   COMM:<VBoxService> PATH: /var/run/utmp
2025-07-02 20:20:15,464 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /usr/local/share/dbus-1/system-services
2025-07-02 20:20:15,464 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /usr/share/dbus-1/system-services
2025-07-02 20:20:15,464 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /lib/dbus-1/system-services
2025-07-02 20:20:15,464 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 538    COMM:<dbus-daemon> PATH: /var/lib/snapd/dbus-1/system-services/
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/interrupts
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/stat
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/irq/20/smp_affinity
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/irq/0/smp_affinity
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/irq/1/smp_affinity
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/irq/8/smp_affinity
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/irq/12/smp_affinity
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/irq/14/smp_affinity
2025-07-02 20:20:15,602 - INFO - 20:20:15-tracepoint:syscalls:sys_enter_open PID: 547    COMM:<irqbalance> PATH: /proc/irq/15/smp_affinity
2025-07-02 20:20:16,332 - INFO - 20:20:16-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:16,333 - INFO - 20:20:16-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:16,333 - INFO - 20:20:16-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline
2025-07-02 20:20:17,353 - INFO - 20:20:17-tracepoint:syscalls:sys_enter_connect PID: 2590   COMM:<VBoxClient> PATH: 
2025-07-02 20:20:17,354 - INFO - 20:20:17-tracepoint:syscalls:sys_enter_open PID: 2590   COMM:<VBoxClient> PATH: /home/vboxuser/.Xauthority
2025-07-02 20:20:17,354 - INFO - 20:20:17-tracepoint:syscalls:sys_enter_open PID: 2344   COMM:<Xorg> PATH: /proc/2590/cmdline

```
