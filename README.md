# virtualization_security
- 记录一下自己虚拟化安全的进程
- 因为我和resery都没有这方面的经验，所以现在还处在摸着石头过河的阶段，各位共勉吧
## 1st week
- 看了UNIX高级编程前四章，学了一些UNIX系统的API
- 做了p4 ctf的kvm，wp已经上传
- 调试了一下CVE-2020-14364的exp，知道了usb设备和机器通信的方式:EHCI
- 下周计划:
  - 找一些vm逃逸相关的题目 (对tw的escape me很感兴趣，但是可能超出我自己的能力范围了)
  - 有点不想看UNIX编程了，想去看qemu/kvm源码分析那本书
  - CodeQL学习提上日程
## 2rd week
 - 翻译了一篇GHSlab的文章，初步学习用codeql模式化的描述漏洞，笔记已上传
 - plaidctf2020 sandybox working
   - 沙箱的逻辑已经逆完，但不知道怎么bypass
   - 但是10byte的shellcode有想法，做过类似的题，利用寄存器存了shellcode的地址，通过xchg指令把那个地址移到rdi做参数，然后调用read就可以读更多的shellcode了
 - sandybox看了wp写完了
 - 看了一点深入理解linux内核
 - 看了一个奇安信员工关于虚拟化漏洞挖掘的培训视频，总结一下虚拟化攻击面:
    - 加强guest os使用体验的程序，比如:VMware的vmtools
    - 虚拟化的各种设备驱动，比如sd卡，usb设备等
    - 虚拟化的网络协议栈，比如dhcp协议等
    - 总结一下就是要找guest和host可以进行交互的位置去挖掘，这样才可能造成逃逸
