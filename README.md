### 内核态向用户态进程注入dll

利用APC，从内核态向用户态进程注入DLL。

### 参考链接 

- [https://bbs.pediy.com/thread-209377.htm](https://bbs.pediy.com/thread-209377.htm)

- [https://www.jianshu.com/p/cae122c2f7fb](https://www.jianshu.com/p/cae122c2f7fb)

- [https://www.cnblogs.com/aliflycoris/p/5353269.html](https://www.cnblogs.com/aliflycoris/p/5353269.html)


- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FLdrLoadDll.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FLdrLoadDll.html)


- [https://github.com/mic101/windows](https://github.com/mic101/windows)

- [https://alexvogtkernel.blogspot.com/2018/09/kernel-injection-code-reversing-sirifef.html](https://alexvogtkernel.blogspot.com/2018/09/kernel-injection-code-reversing-sirifef.html)


### build 

直接用vs2017打开，编译即可。需要修改一下 dll的路径。


### Limitations 

不支持 wow64 process. 
