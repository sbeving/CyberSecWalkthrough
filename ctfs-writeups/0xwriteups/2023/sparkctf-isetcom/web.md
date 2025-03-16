---
description: Here you'll find different Web tasks solved step-by-step
---

# 🕸️ Web

### Inspector

<figure><img src="../../../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

First web tasks are beginner friendly in this case the flag will be found in the files of the website

Let's start by hitting **CTRL + SHIFT + i** in the website then go to Sources

<figure><img src="../../../../.gitbook/assets/image (43).png" alt=""><figcaption><p>1st part of the flag</p></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (49).png" alt=""><figcaption><p>2nd part of the flag</p></figcaption></figure>

### Beji Matrix

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

I opened the sources to fetch for the flag all I ever found was a JS function called **flag()** calling another function called **hex\_to\_ascii()**

<figure><img src="../../../../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

I went to the console and called **flag()**

<figure><img src="../../../../.gitbook/assets/image (55).png" alt=""><figcaption><p>&#x26; The flag was given</p></figcaption></figure>

### Headers

<figure><img src="../../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

**HTTP header fields** are a list of [strings](https://en.wikipedia.org/wiki/String_\(computer_science\)) sent and received by both the client program and server on every HTTP request and response.

If you visit the website you'll find "Hello there, did you check your head?" as a message&#x20;

To check headers hit **CTRL + SHIFT + i** then Network then reload the page

<figure><img src="../../../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

Flag is given under flag Header

### Verbz

<figure><img src="../../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

There are various HTTP methods but in this case a hint was given&#x20;

We need to use the OPTIONS method

<figure><img src="../../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

Curling the website w/ the OPTIONS method gave us the flag



### Replace

<figure><img src="../../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

The given file contains this PHP code :&#x20;

```php
<?php
// flag is at flag.txt
show_source('index.php'); 

if (isset($_GET['file'])){ // if file parameter is set
    $file = $_GET['file'];
    $clean_file = preg_replace('/flag/i','',$file); //Removes flag from parameter
    echo file_get_contents($clean_file);
}else{
    echo "pls hax me";
}
?>
```

As "flag" is removed, I tricked the function with flag within every character of the word like this       ?file=<mark style="color:red;">**f**</mark>flag<mark style="color:red;">**l**</mark>flag<mark style="color:red;">**a**</mark>flag<mark style="color:red;">**g.txt**</mark> and It returned our flag

> Spark{preg\_replace\_ftw!!}

### Gift

<figure><img src="../../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>



As I visited the Web page,All I ever found was a simple \<a> Tag referring to "/ca&#x6E;_&#x79;#&#x75;_&#x67;et\__the\__&#x66;lag?!" --> I did notice that the URL needs [`Encoding`](https://www.urlencoder.org)

& It became /cany%23uget\_the\_flag%3F%21 then I got the flag

> Spark{Helo-UwU-noob}

### Adm\_IN

![](<../../../../.gitbook/assets/image (9).png>)



![](<../../../../.gitbook/assets/image (15).png>)



![](<../../../../.gitbook/assets/image (19).png>)

