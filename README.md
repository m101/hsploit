= HEVD Multi-Exploit by m\_101

== Introduction

There are many exploits and write-ups for the HEVD training driver,
here is another multi-exploit.

There is a lot of documentation as how this driver can be exploited,
so I will not expand more on that part.

However, the goal of my release is to have a Rust example of using C calls
and that yes you can code Windows kernel exploits without leaving Linux
for compilation and not having to install Visual Studio.
Another advantage is that the generated binary is self contained,
no external dependencies are needed for the exploit but the binary itself.

Other aspects of this multi-exploit compared to the published ones are:
- A token stealing payload written so it doesn't BSoD the OS since it increases
the token reference counter. Yay, infinite successful exploitation.
- Arbitrary Overwrite : HalDispatchTable+4 original value is restored after
privilege escalation. The hardcoded offset used for calculation is specific
to the Windows version I developed the exploit for.

Fixing what has been corrupted is extremely important in order to have
a crashless exploit. I will detail the "algorithm" to resolve the original
value.

== Pre-requisite

- Install rust toolchain : https://rustup.rs/
- Windows 7 x86
- HEVD

== Implemented payloads and techniques

Payloads:
- Token stealing payload that updates the reference counter of the stolen token

Techniques used:
* Windows 7
- Basic kernel pool spraying based on Event objects
- Kernel pool overflow corrupting the TypeIndex field + NULL page crafting
- Stack spraying using NtMapUserPhysicalPages() (thanks to @j00ru)

== Dynamically resolving HaliQuerySystemInformation

You can use a PE parser and Capstone to do the job.

HalDispatchTable+4 contains the address of the HaliQuerySystemInformation
function.
In order to dynamically resolve its address, you can use the following
algorithm :
- Open/Load hal.dll
- Resolve HalInitSystem
- Following the proper jmp, this will end up jumping to HalpInitSystem
- Follow HalpInitSystem code until you stumble upon the HalDispatchTable
initialization.

There will be a pattern looking like this:
mov dword ptr [eax + 4], HaliQuerySystemInformation

Now you have the RVA you need.

Add the HAL base to that RVA and you got the address of HaliQuerySystemInformation.

I have implemented a PoC of that hunting algorithm using my custom PE parser,
I won't be releasing my PE parser code but you can use goblin to do the same.

== That's it

Hope you enjoy reading the code.

Cheers,

m\_101

